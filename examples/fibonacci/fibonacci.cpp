
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

int main() {
    try {
        constexpr std::size_t ROWS=32, WIDTH=2;
        std::array<std::array<u64,WIDTH>,ROWS> trace{};
        trace[0]={1,1};
        for(std::size_t r=1;r<ROWS;++r) {
            trace[r][0]=trace[r-1][1];
            trace[r][1]=add(trace[r-1][0],trace[r-1][1]);
        }
        std::size_t residuals=0;
        if(trace[0][0]!=1 || trace[0][1]!=1) throw std::runtime_error("boundary constraint failure");
        residuals += 2;
        for(std::size_t r=0;r+1<ROWS;++r) {
            if(trace[r+1][0]!=trace[r][1]) throw std::runtime_error("transition constraint 0 failure");
            if(trace[r+1][1]!=add(trace[r][0],trace[r][1])) throw std::runtime_error("transition constraint 1 failure");
            residuals += 2;
        }
        u64 h=14695981039346656037ULL;
        for(const auto& row:trace) for(u64 x:row) h=fnv_word(h,x);
        std::cout<<"status=PASS\n"
                 <<"air_id=QMG-AIR-FIBONACCI\n"
                 <<"air_revision=1\n"
                 <<"backend=cpp\n"
                 <<"trace_rows="<<ROWS<<"\n"
                 <<"trace_width="<<WIDTH<<"\n"
                 <<"maximum_constraint_degree=1\n"
                 <<"constraint_residuals="<<residuals<<"\n"
                 <<"trace_fingerprint="<<std::hex<<std::setfill('0')<<std::setw(16)<<h<<std::dec<<"\n"
                 <<"public_output_0="<<trace.back()[0]<<"\n"
                 <<"public_output_1="<<trace.back()[1]<<"\n";
        return 0;
    } catch(const std::exception& e) {
        std::cerr<<"status=FAIL\nerror="<<e.what()<<"\n";
        return 1;
    }
}
