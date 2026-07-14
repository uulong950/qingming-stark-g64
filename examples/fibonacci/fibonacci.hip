
#include <hip/hip_runtime.h>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <vector>

using u64=std::uint64_t;
using u128=unsigned __int128;
static constexpr u64 P=0xffffffff00000001ULL;

static void hip_check(hipError_t status,const char* expr,const char* file,int line){
    if(status!=hipSuccess) throw std::runtime_error(std::string("HIP error: ")+hipGetErrorString(status)+" in "+expr+" at "+file+":"+std::to_string(line));
}
#define HIP_CHECK(expr) hip_check((expr),#expr,__FILE__,__LINE__)

__host__ __device__ static inline u64 add(u64 a,u64 b){
#ifndef __HIP_DEVICE_COMPILE__
    return static_cast<u64>((static_cast<u128>(a)+b)%P);
#else
    u64 r=a+b;
    if(r<a) r+=0xffffffffULL;
    if(r>=P) r-=P;
    return r;
#endif
}
static inline u64 fnv_word(u64 h,u64 x){
    for(int i=0;i<8;++i){h^=static_cast<unsigned char>(x>>(8*i));h*=1099511628211ULL;}
    return h;
}
__global__ void build_trace(u64* trace,unsigned* error_count){
    if(blockIdx.x||threadIdx.x)return;
    constexpr int rows=32;
    trace[0]=1;trace[1]=1;
    for(int r=1;r<rows;++r){
        trace[r*2]=trace[(r-1)*2+1];
        trace[r*2+1]=add(trace[(r-1)*2],trace[(r-1)*2+1]);
    }
    unsigned errors=0;
    if(trace[0]!=1||trace[1]!=1)++errors;
    for(int r=0;r+1<rows;++r){
        if(trace[(r+1)*2]!=trace[r*2+1])++errors;
        if(trace[(r+1)*2+1]!=add(trace[r*2],trace[r*2+1]))++errors;
    }
    *error_count=errors;
}
int main(){
    u64* trace=nullptr;
    unsigned* error_count=nullptr;
    try{
        HIP_CHECK(hipMalloc(reinterpret_cast<void**>(&trace),32*2*sizeof(u64)));
        HIP_CHECK(hipMalloc(reinterpret_cast<void**>(&error_count),sizeof(unsigned)));
        build_trace<<<1,1>>>(trace,error_count);
        HIP_CHECK(hipGetLastError());
        HIP_CHECK(hipDeviceSynchronize());
        std::vector<u64> host_trace(32*2);
        unsigned errors=0;
        HIP_CHECK(hipMemcpy(host_trace.data(),trace,host_trace.size()*sizeof(u64),hipMemcpyDeviceToHost));
        HIP_CHECK(hipMemcpy(&errors,error_count,sizeof(errors),hipMemcpyDeviceToHost));
        HIP_CHECK(hipFree(trace));trace=nullptr;
        HIP_CHECK(hipFree(error_count));error_count=nullptr;
        if(errors)throw std::runtime_error("AIR constraint failure");
        u64 h=14695981039346656037ULL;
        for(u64 x:host_trace)h=fnv_word(h,x);
        std::cout<<"status=PASS\n"
                 <<"air_id=QMG-AIR-FIBONACCI\n"
                 <<"air_revision=1\n"
                 <<"backend=hip\n"
                 <<"trace_rows=32\n"
                 <<"trace_width=2\n"
                 <<"maximum_constraint_degree=1\n"
                 <<"constraint_residuals=64\n"
                 <<"trace_fingerprint="<<std::hex<<std::setfill('0')<<std::setw(16)<<h<<std::dec<<"\n"
                 <<"public_output_0="<<host_trace[62]<<"\n"
                 <<"public_output_1="<<host_trace[63]<<"\n";
        return 0;
    }catch(const std::exception& e){
        if(trace)(void)hipFree(trace);
        if(error_count)(void)hipFree(error_count);
        std::cerr<<"status=FAIL\nerror="<<e.what()<<"\n";
        return 1;
    }
}
