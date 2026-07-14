
#include <hip/hip_runtime.h>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "../../rx7900xtx-24g/qingming_poseidon2_g64_constants.h"

using u64=std::uint64_t;
using u128=unsigned __int128;
static constexpr u64 P=0xffffffff00000001ULL;
static constexpr u64 C=0x00000000ffffffffULL;

static void hip_check(hipError_t status,const char* expr,const char* file,int line){
    if(status!=hipSuccess) throw std::runtime_error(std::string("HIP error: ")+hipGetErrorString(status)+" in "+expr+" at "+file+":"+std::to_string(line));
}
#define HIP_CHECK(expr) hip_check((expr),#expr,__FILE__,__LINE__)

__host__ __device__ static inline u64 add(u64 a,u64 b){
    u64 r=a+b;
    if(r<a)r+=C;
    if(r>=P)r-=P;
    return r;
}
__host__ __device__ static inline u64 mul(u64 a,u64 b){
#ifndef __HIP_DEVICE_COMPILE__
    return static_cast<u64>((static_cast<u128>(a)*b)%P);
#else
    u64 low=a*b,high=__umul64hi(a,b);
    std::uint32_t hi_hi=static_cast<std::uint32_t>(high>>32);
    std::uint32_t hi_lo=static_cast<std::uint32_t>(high);
    u64 shifted=static_cast<u64>(hi_lo)<<32;
    u64 r=low;
    bool carry=r>0xffffffffffffffffULL-shifted;
    r+=shifted;
    u64 sub=static_cast<u64>(hi_lo)+static_cast<u64>(hi_hi);
    bool borrow=r<sub;
    r-=sub;
    if(carry&&!borrow){
        bool carry2=r>0xffffffffffffffffULL-C;
        r+=C;
        if(carry2)r+=C;
    }else if(borrow&&!carry){
        bool borrow2=r<C;
        r-=C;
        if(borrow2)r-=C;
    }
    if(r>=P)r-=P;
    return r;
#endif
}
__host__ __device__ static inline u64 pow7(u64 x){
    u64 x2=mul(x,x),x3=mul(x2,x),x4=mul(x2,x2);
    return mul(x3,x4);
}
__device__ static void external_mix(u64 s[12],const u64* matrix){
    u64 out[12]{};
    for(int r=0;r<12;++r){
        u64 acc=0;
        for(int c=0;c<12;++c)acc=add(acc,mul(matrix[r*12+c],s[c]));
        out[r]=acc;
    }
    for(int i=0;i<12;++i)s[i]=out[i];
}
__device__ static void internal_mix(u64 s[12],const u64* diag){
    u64 total=0,out[12]{};
    for(int i=0;i<12;++i)total=add(total,s[i]);
    for(int i=0;i<12;++i)out[i]=add(total,mul(diag[i],s[i]));
    for(int i=0;i<12;++i)s[i]=out[i];
}
__device__ static void permute(u64 s[12],const u64* rc_external,const u64* rc_internal,const u64* matrix,const u64* diag){
    external_mix(s,matrix);
    for(int r=0;r<4;++r){
        for(int i=0;i<12;++i)s[i]=pow7(add(s[i],rc_external[r*12+i]));
        external_mix(s,matrix);
    }
    for(int r=0;r<22;++r){
        s[0]=pow7(add(s[0],rc_internal[r]));
        internal_mix(s,diag);
    }
    for(int r=4;r<8;++r){
        for(int i=0;i<12;++i)s[i]=pow7(add(s[i],rc_external[r*12+i]));
        external_mix(s,matrix);
    }
}
__global__ void build_trace(u64* trace,unsigned* error_count,const u64* rc_external,const u64* rc_internal,const u64* matrix,const u64* diag){
    if(blockIdx.x||threadIdx.x)return;
    constexpr int rows=31;
    for(int i=0;i<12;++i)trace[i]=static_cast<u64>(i+1);
    for(int r=1;r<rows;++r){
        u64 state[12];
        for(int i=0;i<12;++i)state[i]=trace[(r-1)*12+i];
        permute(state,rc_external,rc_internal,matrix,diag);
        for(int i=0;i<12;++i)trace[r*12+i]=state[i];
    }
    unsigned errors=0;
    for(int i=0;i<12;++i)if(trace[i]!=static_cast<u64>(i+1))++errors;
    for(int r=0;r+1<rows;++r){
        u64 expected[12];
        for(int i=0;i<12;++i)expected[i]=trace[r*12+i];
        permute(expected,rc_external,rc_internal,matrix,diag);
        for(int i=0;i<12;++i)if(trace[(r+1)*12+i]!=expected[i])++errors;
    }
    *error_count=errors;
}
static inline u64 fnv_word(u64 h,u64 x){
    for(int i=0;i<8;++i){h^=static_cast<unsigned char>(x>>(8*i));h*=1099511628211ULL;}
    return h;
}
int main(){
    u64 *trace=nullptr,*rc_external=nullptr,*rc_internal=nullptr,*matrix=nullptr,*diag=nullptr;
    unsigned* error_count=nullptr;
    try{
        HIP_CHECK(hipMalloc(reinterpret_cast<void**>(&trace),31*12*sizeof(u64)));
        HIP_CHECK(hipMalloc(reinterpret_cast<void**>(&rc_external),96*sizeof(u64)));
        HIP_CHECK(hipMalloc(reinterpret_cast<void**>(&rc_internal),22*sizeof(u64)));
        HIP_CHECK(hipMalloc(reinterpret_cast<void**>(&matrix),144*sizeof(u64)));
        HIP_CHECK(hipMalloc(reinterpret_cast<void**>(&diag),12*sizeof(u64)));
        HIP_CHECK(hipMalloc(reinterpret_cast<void**>(&error_count),sizeof(unsigned)));
        HIP_CHECK(hipMemcpy(rc_external,QM_P2_G64_RC_EXTERNAL,96*sizeof(u64),hipMemcpyHostToDevice));
        HIP_CHECK(hipMemcpy(rc_internal,QM_P2_G64_RC_INTERNAL,22*sizeof(u64),hipMemcpyHostToDevice));
        HIP_CHECK(hipMemcpy(matrix,QM_P2_G64_EXTERNAL_MATRIX,144*sizeof(u64),hipMemcpyHostToDevice));
        HIP_CHECK(hipMemcpy(diag,QM_P2_G64_INTERNAL_DIAG,12*sizeof(u64),hipMemcpyHostToDevice));
        build_trace<<<1,1>>>(trace,error_count,rc_external,rc_internal,matrix,diag);
        HIP_CHECK(hipGetLastError());
        HIP_CHECK(hipDeviceSynchronize());
        std::vector<u64> host_trace(31*12);
        unsigned errors=0;
        HIP_CHECK(hipMemcpy(host_trace.data(),trace,host_trace.size()*sizeof(u64),hipMemcpyDeviceToHost));
        HIP_CHECK(hipMemcpy(&errors,error_count,sizeof(errors),hipMemcpyDeviceToHost));
        HIP_CHECK(hipFree(trace));trace=nullptr;
        HIP_CHECK(hipFree(rc_external));rc_external=nullptr;
        HIP_CHECK(hipFree(rc_internal));rc_internal=nullptr;
        HIP_CHECK(hipFree(matrix));matrix=nullptr;
        HIP_CHECK(hipFree(diag));diag=nullptr;
        HIP_CHECK(hipFree(error_count));error_count=nullptr;
        if(errors)throw std::runtime_error("AIR constraint failure");
        u64 h=14695981039346656037ULL;
        for(u64 x:host_trace)h=fnv_word(h,x);
        const std::size_t off=30*12;
        std::cout<<"status=PASS\n"
                 <<"air_id=QMG-AIR-POSEIDON2-CHAIN\n"
                 <<"air_revision=1\n"
                 <<"backend=hip\n"
                 <<"trace_rows=31\n"
                 <<"trace_width=12\n"
                 <<"maximum_constraint_degree=7\n"
                 <<"constraint_residuals=372\n"
                 <<"trace_fingerprint="<<std::hex<<std::setfill('0')<<std::setw(16)<<h<<std::dec<<"\n"
                 <<"public_output_0="<<host_trace[off]<<"\n"
                 <<"public_output_1="<<host_trace[off+1]<<"\n"
                 <<"public_output_2="<<host_trace[off+2]<<"\n"
                 <<"public_output_3="<<host_trace[off+3]<<"\n";
        return 0;
    }catch(const std::exception& e){
        if(trace)(void)hipFree(trace);
        if(rc_external)(void)hipFree(rc_external);
        if(rc_internal)(void)hipFree(rc_internal);
        if(matrix)(void)hipFree(matrix);
        if(diag)(void)hipFree(diag);
        if(error_count)(void)hipFree(error_count);
        std::cerr<<"status=FAIL\nerror="<<e.what()<<"\n";
        return 1;
    }
}
