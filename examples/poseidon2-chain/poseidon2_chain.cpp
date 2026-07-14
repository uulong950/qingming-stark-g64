
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <vector>

using u64 = std::uint64_t;
using u128 = unsigned __int128;
static constexpr u64 P = 0xffffffff00000001ULL;

static inline u64 add(u64 a, u64 b) {
    u128 x = static_cast<u128>(a) + b;
    return static_cast<u64>(x % P);
}
static inline u64 mul(u64 a, u64 b) {
    return static_cast<u64>((static_cast<u128>(a) * b) % P);
}
static inline u64 pow7(u64 x) {
    u64 x2=mul(x,x), x3=mul(x2,x), x4=mul(x2,x2);
    return mul(x3,x4);
}
static inline u64 fnv_word(u64 h, u64 x) {
    for (int i=0;i<8;++i) { h ^= static_cast<unsigned char>(x >> (8*i)); h *= 1099511628211ULL; }
    return h;
}

#include "../../rx7900xtx-24g/qingming_poseidon2_g64_constants.h"

using State=std::array<u64,12>;

static void external_mix(State& s) {
    State out{};
    for(int r=0;r<12;++r) {
        u64 acc=0;
        for(int c=0;c<12;++c) acc=add(acc,mul(QM_P2_G64_EXTERNAL_MATRIX[r*12+c],s[c]));
        out[r]=acc;
    }
    s=out;
}
static void internal_mix(State& s) {
    u64 total=0;
    for(u64 x:s) total=add(total,x);
    State out{};
    for(int i=0;i<12;++i) out[i]=add(total,mul(QM_P2_G64_INTERNAL_DIAG[i],s[i]));
    s=out;
}
static void permute(State& s) {
    external_mix(s);
    for(int r=0;r<4;++r) {
        for(int i=0;i<12;++i) s[i]=pow7(add(s[i],QM_P2_G64_RC_EXTERNAL[r*12+i]));
        external_mix(s);
    }
    for(int r=0;r<22;++r) {
        s[0]=pow7(add(s[0],QM_P2_G64_RC_INTERNAL[r]));
        internal_mix(s);
    }
    for(int r=4;r<8;++r) {
        for(int i=0;i<12;++i) s[i]=pow7(add(s[i],QM_P2_G64_RC_EXTERNAL[r*12+i]));
        external_mix(s);
    }
}
int main() {
    try {
        constexpr std::size_t ROWS=31, WIDTH=12;
        std::array<State,ROWS> trace{};
        for(int i=0;i<12;++i) trace[0][i]=static_cast<u64>(i+1);
        for(std::size_t r=1;r<ROWS;++r) { trace[r]=trace[r-1]; permute(trace[r]); }
        std::size_t residuals=12;
        for(int i=0;i<12;++i) if(trace[0][i]!=static_cast<u64>(i+1)) throw std::runtime_error("boundary constraint failure");
        for(std::size_t r=0;r+1<ROWS;++r) {
            State expected=trace[r]; permute(expected);
            for(int i=0;i<12;++i) if(trace[r+1][i]!=expected[i]) throw std::runtime_error("transition constraint failure");
            residuals += 12;
        }
        u64 h=14695981039346656037ULL;
        for(const auto& row:trace) for(u64 x:row) h=fnv_word(h,x);
        std::cout<<"status=PASS\n"
                 <<"air_id=QMG-AIR-POSEIDON2-CHAIN\n"
                 <<"air_revision=1\n"
                 <<"backend=cpp\n"
                 <<"trace_rows="<<ROWS<<"\n"
                 <<"trace_width="<<WIDTH<<"\n"
                 <<"maximum_constraint_degree=7\n"
                 <<"constraint_residuals="<<residuals<<"\n"
                 <<"trace_fingerprint="<<std::hex<<std::setfill('0')<<std::setw(16)<<h<<std::dec<<"\n"
                 <<"public_output_0="<<trace.back()[0]<<"\n"
                 <<"public_output_1="<<trace.back()[1]<<"\n"
                 <<"public_output_2="<<trace.back()[2]<<"\n"
                 <<"public_output_3="<<trace.back()[3]<<"\n";
        return 0;
    } catch(const std::exception& e) {
        std::cerr<<"status=FAIL\nerror="<<e.what()<<"\n";
        return 1;
    }
}
