// QINGMING-STARK-G64 single-file C++ CPU reference.
// SPDX-License-Identifier: Apache-2.0
//
// Commands:
//   qingming_stark_g64 test
//   qingming_stark_g64 vectors
//   qingming_stark_g64 scale-contract
//   qingming_stark_g64 scale-table
//   qingming_stark_g64 scale-run K
//   qingming_stark_g64 scale-matrix [K_MIN] [K_MAX]
//   qingming_stark_g64 bench [trace_log2]
//
// This is a correctness-first reference. Goldilocks multiplication uses
// unsigned __int128. The proof cycle implements the frozen 64-column AIR,
// radix-2 NTT/LDE, composition quotient, Poseidon2 Merkle commitments,
// binary FRI, canonical proof encoding, and fail-closed verification.

#include <algorithm>
#include <bit>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iomanip>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace qm {

static constexpr uint64_t P = 0xffffffff00000001ULL;
static constexpr uint64_t GENERATOR = 7;
static constexpr size_t WIDTH = 12, RATE = 8, DIGEST_LEN = 4;
static constexpr size_t AIR_LANES = 16, AIR_WIDTH = 64;
static constexpr size_t BLOWUP = 8, QUERY_COUNT = 64, TERMINAL_SIZE = 16;
static constexpr uint64_t PARAM_FP = 0xad77784b434bb34cULL;
static constexpr uint64_t VECTOR_FP = 0xffdf9225a1834ebcULL;

struct F {
    uint64_t v = 0;
    F() = default;
    explicit F(uint64_t x): v(x >= P ? x - P : x) {}
    static std::optional<F> canonical(uint64_t x) {
        if (x >= P) return std::nullopt;
        return F(x);
    }
    F operator+(F o) const {
        unsigned __int128 x = (unsigned __int128)v + o.v;
        return F((uint64_t)(x % P));
    }
    F operator-(F o) const {
        return v >= o.v ? F(v-o.v) : F(P-(o.v-v));
    }
    F operator*(F o) const {
        unsigned __int128 x = (unsigned __int128)v * o.v;
        return F((uint64_t)(x % P));
    }
    F operator/(F o) const { return *this * o.inv(); }
    F& operator+=(F o){ *this=*this+o; return *this; }
    F& operator-=(F o){ *this=*this-o; return *this; }
    F& operator*=(F o){ *this=*this*o; return *this; }
    bool operator==(F o) const { return v==o.v; }
    bool operator!=(F o) const { return v!=o.v; }
    F pow(uint64_t e) const {
        F b=*this, r(1);
        while(e){ if(e&1) r*=b; b*=b; e>>=1; }
        return r;
    }
    F inv() const {
        if(v==0) throw std::runtime_error("inverse of zero");
        return pow(P-2);
    }
};
inline F operator*(uint64_t a, F b){ return F(a)*b; }

struct E {
    F a{}, b{};
    E() = default;
    E(F x, F y=F{}): a(x), b(y) {}
    E operator+(E o) const { return {a+o.a,b+o.b}; }
    E operator-(E o) const { return {a-o.a,b-o.b}; }
    E operator*(E o) const {
        return {a*o.a + F(7)*(b*o.b), a*o.b+b*o.a};
    }
    E operator*(F x) const { return {a*x,b*x}; }
    E operator/(F x) const { return *this*x.inv(); }
    E& operator+=(E o){ *this=*this+o; return *this; }
    E& operator*=(E o){ *this=*this*o; return *this; }
    bool operator==(E o) const { return a==o.a && b==o.b; }
    bool operator!=(E o) const { return !(*this==o); }
    E pow(uint64_t e) const {
        E x=*this, r(F(1));
        while(e){ if(e&1) r*=x; x*=x; e>>=1; }
        return r;
    }
    E inv() const {
        F n=a*a-F(7)*(b*b);
        F ni=n.inv();
        return {a*ni,F(0)-b*ni};
    }
};

using Digest=std::array<F,DIGEST_LEN>;
using State=std::array<F,WIDTH>;
using Row=std::array<F,AIR_WIDTH>;

enum class Domain:size_t {
    Permutation=0, Hash=1, Leaf=2, Node=3, Fri=4, Transcript=5
};

static constexpr uint64_t RC_EXT[96] = {
    0x0b076c9815e150a0ULL, 0xb7cf86203d363b0aULL, 0xde03f4cb664f1bc6ULL, 0x74943c07ec7efa51ULL,
    0x63fbc38b42e086cbULL, 0x22eb9f8c147fb7a0ULL, 0x51d15b40772ee69dULL, 0x6ef868441cfd681aULL,
    0xd0defa5b34606ca7ULL, 0x8576810cf3404b1dULL, 0x6f0aa8bd2408c611ULL, 0x226c2c863a3f8d19ULL,
    0x21c53f5ae2809078ULL, 0xc8831bc847540d42ULL, 0x4bd92fc616521496ULL, 0x14be24c87353c837ULL,
    0x45df5e726aadeb6bULL, 0x27dc81ac2dcd4336ULL, 0xffcf1d29b3a89ad8ULL, 0x972fc8a5923b9e23ULL,
    0xbf8aec8e44580cf4ULL, 0x6d06be20765eed44ULL, 0x372237c13f745e49ULL, 0xcaafd3713802689dULL,
    0x54ddfadcde987ad7ULL, 0x8ccb575f8a5133ffULL, 0x7b1db7bc8a67d165ULL, 0xc966242795cce80eULL,
    0xfe2342bf74fc16e3ULL, 0x1d65ca66c5e35627ULL, 0xc2b01aef77fa4021ULL, 0x45c9d816750eda7dULL,
    0x9a546db1904b9d38ULL, 0x40d367bf6b367c5dULL, 0x43428a669040cafdULL, 0xa6832107c92e41edULL,
    0xc99c50f22dfd27a1ULL, 0x2e17386f90bf5580ULL, 0x12d391accb7b790aULL, 0xebd5c9c1667b6303ULL,
    0x10a4cf9430f01a86ULL, 0x089ba3b2605a3a39ULL, 0x0e5c2d8405573d2dULL, 0xf34465d2a47a768dULL,
    0xe86e9adfd7e18db8ULL, 0xf4aed4f4a91f944eULL, 0xb6aa6500c788f221ULL, 0x72a39df30b1cbf43ULL,
    0x4f106841a5afb226ULL, 0x6531cf4716443cb0ULL, 0x0c1361de5a72f7aaULL, 0xaa5d699563835b24ULL,
    0xbefb4e4682f823acULL, 0xbf79ae73ee3b4759ULL, 0xea50f3230ab83ff7ULL, 0x9016d5f3d6bfbd5cULL,
    0xaa2aecb411021ae4ULL, 0x95a3119d1fb2182bULL, 0x4e14282eca3bfad7ULL, 0x1c7784d0d72cfb4dULL,
    0xd9c670470bda32a7ULL, 0x8ae140eb11658f91ULL, 0x7dfd2c7f25e304c8ULL, 0x09e528364ba06100ULL,
    0x498050c8a97ce032ULL, 0x27a7ea1ab98b243cULL, 0xdff63ffe44fd2952ULL, 0xf6eea4c587dd44cdULL,
    0xf19ebf6b5a07b8a0ULL, 0x33029c811d2b7151ULL, 0x007748756eae3bf9ULL, 0x33256d1225d2db57ULL,
    0x00f0367194f6691cULL, 0x714dc8081a8d0d6cULL, 0x5736c450d9da45faULL, 0x2450c7ba79945a75ULL,
    0x552a068235886ce3ULL, 0x72d000f0d5208986ULL, 0x27991057cd3a021cULL, 0xcf61be5d2aa4e84aULL,
    0xa4c2247134e84361ULL, 0xd9517f33121cf36dULL, 0x382d3738386464b8ULL, 0x3af4ee1d9630925aULL,
    0x21f22cb6d3a94971ULL, 0x38f452094e53421dULL, 0x83d7231efa6a15b0ULL, 0xce22e6f5b256459dULL,
    0x517f83511cded60fULL, 0x718a62786dd336b1ULL, 0x9c1bbf135a61bdb2ULL, 0x2983f8cb26ed7c14ULL,
    0x820f6a56259282d8ULL, 0x4c6c766b6338a1f0ULL, 0x83d9955a505f73faULL, 0x6edd716b1400cee5ULL
};
static constexpr uint64_t RC_INT[22] = {
    0x326defdb73b5a74fULL, 0x12ff33e7d89a7f1bULL, 0xd9b0c5515934a971ULL, 0xe12732a314f7346bULL,
    0x02cf88aeae0c5d32ULL, 0x8a1712dffbd830b3ULL, 0xc48aa0fc6eb801baULL, 0x5a978bb08fa763d1ULL,
    0x106cf3e0a8364b5eULL, 0x5d95fc48ac1f29adULL, 0x2c975dd2e229da68ULL, 0x40cbaf88147700efULL,
    0xc52ad03f2a33a991ULL, 0x1701a33c70808721ULL, 0xeb44ee9881504e1aULL, 0xcc7d4368e3f043bdULL,
    0xa5ccd326e46f7f39ULL, 0x8136de66b6637aa5ULL, 0x33d3db2cd8ca8a7dULL, 0x5d2ffd093df99e7aULL,
    0xe2374063fefecd9fULL, 0x5369d92f39ed6975ULL
};
static constexpr uint64_t EXT_MAT[144] = {
    0x1249249236db6db7ULL, 0xeeeeeeee00000001ULL, 0xefffffff10000001ULL, 0xf0f0f0f000000001ULL,
    0x9c71c71bd5555556ULL, 0x9435e50ce50d7944ULL, 0xf333333240000001ULL, 0x6186186124924925ULL,
    0x3a2e8ba2ae8ba2e9ULL, 0x9bd37a6eb21642c9ULL, 0xf555555460000001ULL, 0xc28f5c2833333334ULL,
    0xeeeeeeee00000001ULL, 0xefffffff10000001ULL, 0xf0f0f0f000000001ULL, 0x9c71c71bd5555556ULL,
    0x9435e50ce50d7944ULL, 0xf333333240000001ULL, 0x6186186124924925ULL, 0x3a2e8ba2ae8ba2e9ULL,
    0x9bd37a6eb21642c9ULL, 0xf555555460000001ULL, 0xc28f5c2833333334ULL, 0xcec4ec4df6276277ULL,
    0xefffffff10000001ULL, 0xf0f0f0f000000001ULL, 0x9c71c71bd5555556ULL, 0x9435e50ce50d7944ULL,
    0xf333333240000001ULL, 0x6186186124924925ULL, 0x3a2e8ba2ae8ba2e9ULL, 0x9bd37a6eb21642c9ULL,
    0xf555555460000001ULL, 0xc28f5c2833333334ULL, 0xcec4ec4df6276277ULL, 0xbda12f678e38e38fULL,
    0xf0f0f0f000000001ULL, 0x9c71c71bd5555556ULL, 0x9435e50ce50d7944ULL, 0xf333333240000001ULL,
    0x6186186124924925ULL, 0x3a2e8ba2ae8ba2e9ULL, 0x9bd37a6eb21642c9ULL, 0xf555555460000001ULL,
    0xc28f5c2833333334ULL, 0xcec4ec4df6276277ULL, 0xbda12f678e38e38fULL, 0x892492489b6db6dcULL,
    0x9c71c71bd5555556ULL, 0x9435e50ce50d7944ULL, 0xf333333240000001ULL, 0x6186186124924925ULL,
    0x3a2e8ba2ae8ba2e9ULL, 0x9bd37a6eb21642c9ULL, 0xf555555460000001ULL, 0xc28f5c2833333334ULL,
    0xcec4ec4df6276277ULL, 0xbda12f678e38e38fULL, 0x892492489b6db6dcULL, 0x8d3dcb08469ee585ULL,
    0x9435e50ce50d7944ULL, 0xf333333240000001ULL, 0x6186186124924925ULL, 0x3a2e8ba2ae8ba2e9ULL,
    0x9bd37a6eb21642c9ULL, 0xf555555460000001ULL, 0xc28f5c2833333334ULL, 0xcec4ec4df6276277ULL,
    0xbda12f678e38e38fULL, 0x892492489b6db6dcULL, 0x8d3dcb08469ee585ULL, 0xf777777680000001ULL,
    0xf333333240000001ULL, 0x6186186124924925ULL, 0x3a2e8ba2ae8ba2e9ULL, 0x9bd37a6eb21642c9ULL,
    0xf555555460000001ULL, 0xc28f5c2833333334ULL, 0xcec4ec4df6276277ULL, 0xbda12f678e38e38fULL,
    0x892492489b6db6dcULL, 0x8d3dcb08469ee585ULL, 0xf777777680000001ULL, 0x9ce739cdd6b5ad6cULL,
    0x6186186124924925ULL, 0x3a2e8ba2ae8ba2e9ULL, 0x9bd37a6eb21642c9ULL, 0xf555555460000001ULL,
    0xc28f5c2833333334ULL, 0xcec4ec4df6276277ULL, 0xbda12f678e38e38fULL, 0x892492489b6db6dcULL,
    0x8d3dcb08469ee585ULL, 0xf777777680000001ULL, 0x9ce739cdd6b5ad6cULL, 0xf7ffffff08000001ULL,
    0x3a2e8ba2ae8ba2e9ULL, 0x9bd37a6eb21642c9ULL, 0xf555555460000001ULL, 0xc28f5c2833333334ULL,
    0xcec4ec4df6276277ULL, 0xbda12f678e38e38fULL, 0x892492489b6db6dcULL, 0x8d3dcb08469ee585ULL,
    0xf777777680000001ULL, 0x9ce739cdd6b5ad6cULL, 0xf7ffffff08000001ULL, 0x26c9b26c745d1746ULL,
    0x9bd37a6eb21642c9ULL, 0xf555555460000001ULL, 0xc28f5c2833333334ULL, 0xcec4ec4df6276277ULL,
    0xbda12f678e38e38fULL, 0x892492489b6db6dcULL, 0x8d3dcb08469ee585ULL, 0xf777777680000001ULL,
    0x9ce739cdd6b5ad6cULL, 0xf7ffffff08000001ULL, 0x26c9b26c745d1746ULL, 0xf878787780000001ULL,
    0xf555555460000001ULL, 0xc28f5c2833333334ULL, 0xcec4ec4df6276277ULL, 0xbda12f678e38e38fULL,
    0x892492489b6db6dcULL, 0x8d3dcb08469ee585ULL, 0xf777777680000001ULL, 0x9ce739cdd6b5ad6cULL,
    0xf7ffffff08000001ULL, 0x26c9b26c745d1746ULL, 0xf878787780000001ULL, 0xd41d41d34924924aULL,
    0xc28f5c2833333334ULL, 0xcec4ec4df6276277ULL, 0xbda12f678e38e38fULL, 0x892492489b6db6dcULL,
    0x8d3dcb08469ee585ULL, 0xf777777680000001ULL, 0x9ce739cdd6b5ad6cULL, 0xf7ffffff08000001ULL,
    0x26c9b26c745d1746ULL, 0xf878787780000001ULL, 0xd41d41d34924924aULL, 0x4e38e38deaaaaaabULL
};
static constexpr uint64_t INT_DIAG[12] = {
    0x45de1a790b7ca367ULL, 0x3b7bc0355c554c31ULL, 0x2ea7837f64608ed1ULL, 0xec08c0bb4ac8d7b6ULL,
    0x92f739c73a48c00aULL, 0x9a27c421c857b6deULL, 0x9053430cf38c54e8ULL, 0x676235d216f0867aULL,
    0x8d00bdc05545249aULL, 0x27b62f800265c059ULL, 0xf6ba33681d8dabccULL, 0x401e54e3de16d979ULL
};
static constexpr uint64_t DOMAIN_TAGS[6] = {
    0xd2fb5fa99c55b924ULL, 0x02d5e8bc7c95bb78ULL, 0xd49a71f4a1e84acaULL, 0x8246b91cbc96cbc1ULL,
    0x01ef068df61d210bULL, 0x5cab39dee3685311ULL
};

inline F pow7(F x){ F x2=x*x, x3=x2*x, x4=x2*x2; return x3*x4; }

void external_mix(State& s){
    State o{};
    for(size_t r=0;r<WIDTH;r++){
        F acc;
        for(size_t c=0;c<WIDTH;c++) acc += F(EXT_MAT[r*WIDTH+c])*s[c];
        o[r]=acc;
    }
    s=o;
}
void internal_mix(State& s){
    F total;
    for(auto x:s) total+=x;
    State o{};
    for(size_t i=0;i<WIDTH;i++) o[i]=total+F(INT_DIAG[i])*s[i];
    s=o;
}
void permute(State& s){
    external_mix(s);
    for(size_t r=0;r<4;r++){
        for(size_t i=0;i<WIDTH;i++) s[i]=pow7(s[i]+F(RC_EXT[r*WIDTH+i]));
        external_mix(s);
    }
    for(size_t r=0;r<22;r++){
        s[0]=pow7(s[0]+F(RC_INT[r]));
        internal_mix(s);
    }
    for(size_t r=4;r<8;r++){
        for(size_t i=0;i<WIDTH;i++) s[i]=pow7(s[i]+F(RC_EXT[r*WIDTH+i]));
        external_mix(s);
    }
}
Digest hash_fields(std::span<const F> vals, Domain d){
    State s{};
    s[RATE]=F(DOMAIN_TAGS[(size_t)d]);
    if(vals.empty()){
        s[0]+=F(1); permute(s);
    }else{
        size_t off=0;
        while(off<vals.size()){
            size_t n=std::min(RATE,vals.size()-off);
            for(size_t i=0;i<n;i++) s[i]+=vals[off+i];
            if(n<RATE) s[n]+=F(1);
            permute(s); off+=n;
        }
    }
    return {s[0],s[1],s[2],s[3]};
}
Digest leaf_hash(uint64_t idx,std::span<const F> vals){
    std::vector<F> x; x.reserve(vals.size()+1); x.push_back(F(idx));
    x.insert(x.end(),vals.begin(),vals.end());
    return hash_fields(x,Domain::Leaf);
}
Digest node_hash(const Digest& l,const Digest& r){
    std::array<F,8> x{};
    std::copy(l.begin(),l.end(),x.begin());
    std::copy(r.begin(),r.end(),x.begin()+4);
    return hash_fields(x,Domain::Node);
}

class Transcript {
    State s_{};
    size_t pos_=0;
    void cycle(){ permute(s_); pos_=0; }
public:
    Transcript(){
        s_[RATE]=F(DOMAIN_TAGS[(size_t)Domain::Transcript]);
        s_[0]=F(PARAM_FP); s_[1]=F(VECTOR_FP); cycle();
    }
    void absorb(Domain d,std::span<const F> vals){
        if(pos_==RATE) cycle();
        s_[pos_++]+=F(DOMAIN_TAGS[(size_t)d]);
        for(F x:vals){ if(pos_==RATE) cycle(); s_[pos_++]+=x; }
        if(pos_==RATE) cycle();
        s_[pos_++]+=F(1); cycle();
    }
    void absorb_digest(Domain d,const Digest& x){ absorb(d,x); }
    F challenge(Domain d){
        std::array<F,1> label{F(DOMAIN_TAGS[(size_t)d])};
        absorb(Domain::Transcript,label);
        F r=s_[0]; cycle(); return r;
    }
    E challenge_ext(){ return {challenge(Domain::Transcript),challenge(Domain::Transcript)}; }
    uint32_t challenge_index(uint32_t n){
        if(n==0 || (n&(n-1))) throw std::runtime_error("index range");
        const uint64_t limit=(P/n)*n;
        for(;;){ uint64_t x=challenge(Domain::Transcript).v; if(x<limit) return (uint32_t)(x%n); }
    }
};

F root_of_unity(uint32_t log_n){
    if(log_n>32) throw std::runtime_error("root size");
    F r=F(GENERATOR).pow((P-1)>>log_n);
    if(r.pow(uint64_t(1)<<log_n)!=F(1)) throw std::runtime_error("bad root");
    if(log_n && r.pow(uint64_t(1)<<(log_n-1))==F(1)) throw std::runtime_error("non-primitive root");
    return r;
}
template<class T> T mul_base(const T& x,F y){ return x*y; }
template<> F mul_base(const F& x,F y){ return x*y; }

template<class T>
void ntt(std::vector<T>& a,bool inverse){
    size_t n=a.size();
    if(n==0 || (n&(n-1))) throw std::runtime_error("ntt size");
    uint32_t lg=0; while((size_t(1)<<lg)<n) lg++;
    for(size_t i=1,j=0;i<n;i++){
        size_t bit=n>>1;
        for(;j&bit;bit>>=1) j^=bit;
        j^=bit;
        if(i<j) std::swap(a[i],a[j]);
    }
    F root=root_of_unity(lg); if(inverse) root=root.inv();
    for(size_t len=2;len<=n;len<<=1){
        F wlen=root.pow(n/len);
        for(size_t i=0;i<n;i+=len){
            F w(1);
            for(size_t j=0;j<len/2;j++){
                T u=a[i+j], v=mul_base(a[i+j+len/2],w);
                a[i+j]=u+v; a[i+j+len/2]=u-v; w*=wlen;
            }
        }
    }
    if(inverse){
        F ni=F((uint64_t)n).inv();
        for(auto& x:a) x=mul_base(x,ni);
    }
}
template<class T>
std::vector<T> lde(const std::vector<T>& evals,size_t blowup,F shift){
    std::vector<T> c=evals; ntt(c,true);
    size_t n=c.size(), m=n*blowup; c.resize(m);
    F p(1);
    for(size_t i=0;i<n;i++){ c[i]=mul_base(c[i],p); p*=shift; }
    ntt(c,false); return c;
}
template<class T>
std::vector<T> interpolate_coset(const std::vector<T>& evals,F offset){
    std::vector<T> c=evals; ntt(c,true);
    F inv=offset.inv(), p(1);
    for(auto& x:c){ x=mul_base(x,p); p*=inv; }
    return c;
}

F lane_const(size_t j){ return F(0x9e3779b97f4a7c15ULL+(uint64_t)j); }
Row initial_row(const std::array<F,16>& init){
    Row r{};
    for(size_t j=0;j<16;j++){
        r[j]=init[j]; r[16+j]=F(0);
        r[32+j]=init[j]*init[(j+1)%16];
        r[48+j]=init[j]*init[j];
    }
    return r;
}
Row next_row(const Row& c){
    Row n{};
    for(size_t j=0;j<16;j++){
        F x=c[j],y=c[(j+1)%16],m=c[32+j],h=c[48+j];
        n[j]=lane_const(j)+x+F(3)*y+F(5)*h+F(7)*m;
        n[16+j]=c[16+j]+m;
    }
    for(size_t j=0;j<16;j++){ n[32+j]=n[j]*n[(j+1)%16]; n[48+j]=n[j]*n[j]; }
    return n;
}
std::vector<Row> make_trace(size_t n,const std::array<F,16>& init){
    if(n<2 || (n&(n-1))) throw std::runtime_error("trace size");
    std::vector<Row> t(n); t[0]=initial_row(init);
    for(size_t i=1;i<n;i++) t[i]=next_row(t[i-1]);
    return t;
}
bool valid_transition(const Row& c,const Row& n){
    for(size_t j=0;j<16;j++){
        F x=c[j],y=c[(j+1)%16],m=c[32+j],h=c[48+j];
        if(m-x*y!=F(0) || h-x*x!=F(0)) return false;
        if(n[16+j]-c[16+j]-m!=F(0)) return false;
        if(n[j]-lane_const(j)-x-F(3)*y-F(5)*h-F(7)*m!=F(0)) return false;
    }
    return true;
}

struct Merkle {
    std::vector<std::vector<Digest>> levels;
    static Merkle build(const std::vector<std::vector<F>>& leaves){
        if(leaves.empty() || (leaves.size()&(leaves.size()-1))) throw std::runtime_error("merkle size");
        Merkle t; t.levels.emplace_back(leaves.size());
        for(size_t i=0;i<leaves.size();i++) t.levels[0][i]=leaf_hash(i,leaves[i]);
        while(t.levels.back().size()>1){
            const auto& p=t.levels.back();
            std::vector<Digest> q(p.size()/2);
            for(size_t i=0;i<q.size();i++) q[i]=node_hash(p[2*i],p[2*i+1]);
            t.levels.push_back(std::move(q));
        }
        return t;
    }
    Digest root() const { return levels.back()[0]; }
    std::vector<Digest> path(size_t idx) const {
        std::vector<Digest> p; p.reserve(levels.size()-1);
        for(size_t l=0;l+1<levels.size();l++){ p.push_back(levels[l][idx^1]); idx>>=1; }
        return p;
    }
};
bool verify_path(uint32_t idx,std::span<const F> vals,const std::vector<Digest>& path,const Digest& root){
    Digest h=leaf_hash(idx,vals);
    uint32_t x=idx;
    for(auto sib:path){ h=(x&1)?node_hash(sib,h):node_hash(h,sib); x>>=1; }
    return h==root;
}
std::vector<F> encode_e(E x){ return {x.a,x.b}; }
std::vector<std::vector<F>> e_leaves(const std::vector<E>& x){
    std::vector<std::vector<F>> r(x.size(),std::vector<F>(2));
    for(size_t i=0;i<x.size();i++){ r[i][0]=x[i].a; r[i][1]=x[i].b; }
    return r;
}

struct PublicInput {
    std::array<F,16> initial{};
    std::array<F,16> final_acc{};
    bool operator==(const PublicInput&) const = default;
};
Digest public_digest(uint32_t log_n,const PublicInput& in){
    std::vector<F> x; x.reserve(33); x.push_back(F(log_n));
    x.insert(x.end(),in.initial.begin(),in.initial.end());
    x.insert(x.end(),in.final_acc.begin(),in.final_acc.end());
    return hash_fields(x,Domain::Hash);
}

E composition_at(
    F z,const Row& c,const Row& n,const PublicInput& pub,E alpha,size_t trace_n,F last
){
    F zn=z.pow((uint64_t)trace_n);
    F ztrans=(zn-F(1))/(z-last);
    F inv_trans=ztrans.inv(), inv_init=(z-F(1)).inv(), inv_final=(z-last).inv();
    E acc, power(F(1));
    auto add=[&](F value,F invz){ acc += power*E(value*invz); power*=alpha; };
    for(size_t j=0;j<16;j++){
        F x=c[j],y=c[(j+1)%16],m=c[32+j],h=c[48+j];
        add(m-x*y,inv_trans);
        add(h-x*x,inv_trans);
        add(n[16+j]-c[16+j]-m,inv_trans);
        add(n[j]-lane_const(j)-x-F(3)*y-F(5)*h-F(7)*m,inv_trans);
    }
    for(size_t j=0;j<16;j++) add(c[j]-pub.initial[j],inv_init);
    for(size_t j=0;j<16;j++) add(c[16+j],inv_init);
    for(size_t j=0;j<16;j++) add(c[16+j]-pub.final_acc[j],inv_final);
    return acc;
}

struct Reader {
    std::span<const uint8_t> b; size_t p=0; bool ok=true;
    uint32_t u32(){
        if(p+4>b.size()){ok=false;return 0;}
        uint32_t x=0;
        for(int i=0;i<4;i++){ x|=uint32_t(b[p++])<<(8*i); }
        return x;
    }
    uint64_t u64(){
        if(p+8>b.size()){ok=false;return 0;}
        uint64_t x=0;
        for(int i=0;i<8;i++){ x|=uint64_t(b[p++])<<(8*i); }
        return x;
    }
    F field(){ auto x=F::canonical(u64()); if(!x){ok=false;return F();} return *x; }
};
void put32(std::vector<uint8_t>& b,uint32_t x){ for(int i=0;i<4;i++) b.push_back(uint8_t(x>>(8*i))); }
void put64(std::vector<uint8_t>& b,uint64_t x){ for(int i=0;i<8;i++) b.push_back(uint8_t(x>>(8*i))); }
void putf(std::vector<uint8_t>& b,F x){ put64(b,x.v); }
void putd(std::vector<uint8_t>& b,const Digest& d){ for(F x:d) putf(b,x); }

struct TraceOpen { Row row{}; std::vector<Digest> path; };
struct FriPair { E lo{},hi{}; std::vector<Digest> plo,phi; };
struct Query { uint32_t idx=0; TraceOpen cur,nxt; std::vector<FriPair> layers; };
struct Proof {
    uint32_t log_n=0;
    PublicInput pub;
    Digest trace_root{}, quotient_root{};
    std::vector<Digest> intermediate_roots;
    std::vector<E> terminal;
    std::vector<Query> queries;
};

std::vector<uint8_t> encode(const Proof& p){
    std::vector<uint8_t> b;
    const char magic[8]={'Q','M','G','6','4','P','0','1'};
    b.insert(b.end(),magic,magic+8); put32(b,1); put32(b,p.log_n);
    for(F x:p.pub.initial){ putf(b,x); }
    for(F x:p.pub.final_acc){ putf(b,x); }
    putd(b,p.trace_root); putd(b,p.quotient_root);
    put32(b,(uint32_t)p.intermediate_roots.size()); for(auto d:p.intermediate_roots) putd(b,d);
    put32(b,(uint32_t)p.terminal.size()); for(E x:p.terminal){putf(b,x.a);putf(b,x.b);}
    put32(b,(uint32_t)p.queries.size());
    for(const Query& q:p.queries){
        put32(b,q.idx);
        for(F x:q.cur.row){ putf(b,x); }
        put32(b,(uint32_t)q.cur.path.size());
        for(auto d:q.cur.path){ putd(b,d); }
        for(F x:q.nxt.row){ putf(b,x); }
        put32(b,(uint32_t)q.nxt.path.size());
        for(auto d:q.nxt.path){ putd(b,d); }
        put32(b,(uint32_t)q.layers.size());
        for(const auto& l:q.layers){
            putf(b,l.lo.a);putf(b,l.lo.b);putf(b,l.hi.a);putf(b,l.hi.b);
            put32(b,(uint32_t)l.plo.size());for(auto d:l.plo)putd(b,d);
            put32(b,(uint32_t)l.phi.size());for(auto d:l.phi)putd(b,d);
        }
    }
    return b;
}
std::optional<Proof> decode(std::span<const uint8_t> bytes){
    Reader r{bytes};
    const char magic[8]={'Q','M','G','6','4','P','0','1'};
    for(int i=0;i<8;i++){ if(r.p>=bytes.size() || bytes[r.p++]!=(uint8_t)magic[i]) r.ok=false; }
    if(r.u32()!=1) r.ok=false;
    Proof p; p.log_n=r.u32();
    if(p.log_n<4 || p.log_n>24) r.ok=false;
    for(auto& x:p.pub.initial){ x=r.field(); }
    for(auto& x:p.pub.final_acc){ x=r.field(); }
    for(auto& x:p.trace_root){ x=r.field(); }
    for(auto& x:p.quotient_root){ x=r.field(); }
    uint32_t nr=r.u32(); if(nr>32)r.ok=false;
    p.intermediate_roots.resize(nr);for(auto& d:p.intermediate_roots)for(auto& x:d)x=r.field();
    uint32_t nt=r.u32(); if(nt!=TERMINAL_SIZE)r.ok=false;
    p.terminal.resize(nt);for(auto& x:p.terminal){x.a=r.field();x.b=r.field();}
    uint32_t nq=r.u32(); if(nq!=QUERY_COUNT)r.ok=false;
    p.queries.resize(nq);
    const uint32_t log_s=p.log_n+3, expected_layers=log_s-4;
    if(nr+1!=expected_layers) r.ok=false;
    auto read_path=[&](uint32_t expected){
        uint32_t n=r.u32(); if(n!=expected)r.ok=false;
        std::vector<Digest> path(n);for(auto& d:path)for(auto& x:d)x=r.field();return path;
    };
    for(auto& q:p.queries){
        q.idx=r.u32(); if(q.idx>=(1u<<log_s))r.ok=false;
        for(auto& x:q.cur.row){ x=r.field(); }
        q.cur.path=read_path(log_s);
        for(auto& x:q.nxt.row){ x=r.field(); }
        q.nxt.path=read_path(log_s);
        uint32_t nl=r.u32(); if(nl!=expected_layers)r.ok=false;
        q.layers.resize(nl);
        for(uint32_t l=0;l<nl;l++){
            auto& x=q.layers[l]; x.lo.a=r.field();x.lo.b=r.field();x.hi.a=r.field();x.hi.b=r.field();
            x.plo=read_path(log_s-l); x.phi=read_path(log_s-l);
        }
    }
    if(r.p!=bytes.size())r.ok=false;
    if(!r.ok){ return std::nullopt; }
    return p;
}

struct ProverData {
    Proof proof;
    std::vector<std::vector<E>> fri_layers;
    std::vector<Merkle> fri_trees;
    std::vector<E> betas;
};

PublicInput statement_for(uint32_t log_n,uint64_t seed){
    PublicInput p;
    for(size_t i=0;i<16;i++) p.initial[i]=F(seed+17*i+1);
    auto t=make_trace(size_t(1)<<log_n,p.initial);
    for(size_t i=0;i<16;i++)p.final_acc[i]=t.back()[16+i];
    return p;
}

ProverData prove(uint32_t log_n,uint64_t seed){
    const size_t n=size_t(1)<<log_n, s=n*BLOWUP;
    PublicInput pub=statement_for(log_n,seed);
    auto trace=make_trace(n,pub.initial);
    std::vector<std::vector<F>> cols(AIR_WIDTH,std::vector<F>(n));
    for(size_t i=0;i<n;i++)for(size_t j=0;j<AIR_WIDTH;j++)cols[j][i]=trace[i][j];
    F shift(GENERATOR);
    std::vector<std::vector<F>> col_lde(AIR_WIDTH);
    for(size_t j=0;j<AIR_WIDTH;j++)col_lde[j]=lde(cols[j],BLOWUP,shift);
    std::vector<std::vector<F>> rows(s,std::vector<F>(AIR_WIDTH));
    for(size_t i=0;i<s;i++)for(size_t j=0;j<AIR_WIDTH;j++)rows[i][j]=col_lde[j][i];
    Merkle trace_tree=Merkle::build(rows);

    Transcript tr;
    Digest pd=public_digest(log_n,pub); tr.absorb_digest(Domain::Hash,pd);
    tr.absorb_digest(Domain::Leaf,trace_tree.root());
    E alpha=tr.challenge_ext();

    F omega_s=root_of_unity(log_n+3), omega_n=root_of_unity(log_n);
    F last=omega_n.inv(), z=shift;
    std::vector<E> q(s);
    for(size_t i=0;i<s;i++){
        Row c{},nx{};
        for(size_t j=0;j<AIR_WIDTH;j++){c[j]=rows[i][j];nx[j]=rows[(i+BLOWUP)%s][j];}
        q[i]=composition_at(z,c,nx,pub,alpha,n,last);
        z*=omega_s;
    }

    ProverData data; data.proof.log_n=log_n; data.proof.pub=pub;
    data.proof.trace_root=trace_tree.root();
    data.fri_layers.push_back(q); data.fri_trees.push_back(Merkle::build(e_leaves(q)));
    data.proof.quotient_root=data.fri_trees[0].root();

    F offset=shift;
    while(data.fri_layers.back().size()>TERMINAL_SIZE){
        const size_t m=data.fri_layers.back().size(), half=m/2;
        Digest current_root=data.fri_trees.back().root();
        tr.absorb_digest(Domain::Fri,current_root);
        E beta=tr.challenge_ext(); data.betas.push_back(beta);
        F omega=root_of_unity((uint32_t)std::countr_zero((uint64_t)m));
        F x=offset, inv2=F(2).inv();
        std::vector<E> next(half);
        for(size_t i=0;i<half;i++){
            E a=data.fri_layers.back()[i], b=data.fri_layers.back()[i+half];
            next[i]=(a+b)*inv2 + beta*((a-b)*(inv2*x.inv()));
            x*=omega;
        }
        offset*=offset;
        if(next.size()>TERMINAL_SIZE){
            data.fri_layers.push_back(next);
            data.fri_trees.push_back(Merkle::build(e_leaves(next)));
            data.proof.intermediate_roots.push_back(data.fri_trees.back().root());
        }else{
            data.proof.terminal=next;
            break;
        }
    }
    std::vector<F> terminal_encoded; terminal_encoded.reserve(2*data.proof.terminal.size());
    for(E x:data.proof.terminal){terminal_encoded.push_back(x.a);terminal_encoded.push_back(x.b);}
    Digest td=hash_fields(terminal_encoded,Domain::Fri); tr.absorb_digest(Domain::Fri,td);

    data.proof.queries.resize(QUERY_COUNT);
    for(size_t qi=0;qi<QUERY_COUNT;qi++){
        Query& qp=data.proof.queries[qi];
        qp.idx=tr.challenge_index((uint32_t)s);
        size_t qidx=qp.idx, qnext=(qidx+BLOWUP)%s;
        for(size_t j=0;j<AIR_WIDTH;j++){qp.cur.row[j]=rows[qidx][j];qp.nxt.row[j]=rows[qnext][j];}
        qp.cur.path=trace_tree.path(qidx); qp.nxt.path=trace_tree.path(qnext);
        qp.layers.resize(data.fri_layers.size());
        size_t idx=qidx;
        for(size_t l=0;l<data.fri_layers.size();l++){
            size_t m=data.fri_layers[l].size(), half=m/2, base=idx%half;
            auto& fp=qp.layers[l];
            fp.lo=data.fri_layers[l][base]; fp.hi=data.fri_layers[l][base+half];
            fp.plo=data.fri_trees[l].path(base); fp.phi=data.fri_trees[l].path(base+half);
            idx=base;
        }
    }
    return data;
}

bool terminal_degree_ok(const std::vector<E>& terminal,F offset,size_t bound){
    auto c=interpolate_coset(terminal,offset);
    for(size_t i=bound;i<c.size();i++)if(c[i]!=E())return false;
    return true;
}

bool verify(const std::vector<uint8_t>& bytes,const PublicInput& expected_pub){
    try{
        auto op=decode(bytes); if(!op)return false; const Proof& p=*op;
        if(!(p.pub==expected_pub))return false;
        const size_t n=size_t(1)<<p.log_n,s=n*BLOWUP;
        Transcript tr; Digest pd=public_digest(p.log_n,expected_pub); tr.absorb_digest(Domain::Hash,pd);
        tr.absorb_digest(Domain::Leaf,p.trace_root); E alpha=tr.challenge_ext();
        std::vector<Digest> roots; roots.push_back(p.quotient_root);
        roots.insert(roots.end(),p.intermediate_roots.begin(),p.intermediate_roots.end());
        std::vector<E> betas;
        for(auto root:roots){tr.absorb_digest(Domain::Fri,root);betas.push_back(tr.challenge_ext());}
        std::vector<F> te;for(E x:p.terminal){te.push_back(x.a);te.push_back(x.b);}
        tr.absorb_digest(Domain::Fri,hash_fields(te,Domain::Fri));
        std::vector<uint32_t> expected(QUERY_COUNT);
        for(auto& x:expected)x=tr.challenge_index((uint32_t)s);
        F omega_s=root_of_unity(p.log_n+3),omega_n=root_of_unity(p.log_n),last=omega_n.inv();
        F final_offset=F(GENERATOR);
        for(size_t i=0;i<roots.size();i++)final_offset*=final_offset;
        size_t final_bound=n; for(size_t i=0;i<roots.size();i++)final_bound=(final_bound+1)/2;
        if(final_bound>TERMINAL_SIZE || !terminal_degree_ok(p.terminal,final_offset,final_bound))return false;

        for(size_t qi=0;qi<QUERY_COUNT;qi++){
            const Query& q=p.queries[qi]; if(q.idx!=expected[qi])return false;
            uint32_t qnext=(q.idx+BLOWUP)%s;
            if(!verify_path(q.idx,q.cur.row,q.cur.path,p.trace_root))return false;
            if(!verify_path(qnext,q.nxt.row,q.nxt.path,p.trace_root))return false;
            if(q.layers.size()!=roots.size())return false;
            F z=F(GENERATOR)*omega_s.pow(q.idx);
            E expected_value=composition_at(z,q.cur.row,q.nxt.row,expected_pub,alpha,n,last);
            size_t idx=q.idx; F offset(GENERATOR);
            for(size_t l=0;l<roots.size();l++){
                size_t m=s>>l,half=m/2,base=idx%half;
                const auto& fp=q.layers[l];
                auto vlo=encode_e(fp.lo),vhi=encode_e(fp.hi);
                if(!verify_path((uint32_t)base,vlo,fp.plo,roots[l]))return false;
                if(!verify_path((uint32_t)(base+half),vhi,fp.phi,roots[l]))return false;
                E selected=(idx<half)?fp.lo:fp.hi;
                if(selected!=expected_value)return false;
                F x=offset*root_of_unity((uint32_t)std::countr_zero((uint64_t)m)).pow(base);
                E folded=(fp.lo+fp.hi)*F(2).inv()+betas[l]*((fp.lo-fp.hi)*(F(2).inv()*x.inv()));
                expected_value=folded; idx=base; offset*=offset;
            }
            if(p.terminal[idx]!=expected_value)return false;
        }
        return true;
    }catch(...){return false;}
}


uint64_t fnv1a(const std::vector<uint8_t>& b);
std::string hx(uint64_t x);

struct ScaleSpec {
    uint32_t scale_log2 = 0;
    uint32_t trace_log2 = 0;
    uint32_t lde_row_log2 = 0;
    uint64_t total_lde_elements = 0;
    uint64_t lde_rows = 0;
    uint64_t trace_rows = 0;
    uint64_t fri_fold_rounds = 0;
    uint64_t proof_bytes = 0;
    uint64_t raw_lde_bytes = 0;
    uint64_t core_lower_bound_bytes = 0;
};

uint64_t expected_proof_bytes_for_lde_log(uint32_t lde_row_log2) {
    if (lde_row_log2 < 7 || lde_row_log2 > 24) {
        throw std::runtime_error("LDE row log2 must be in 7..24");
    }
    const uint64_t layers = uint64_t(lde_row_log2) - 4;
    const uint64_t intermediate_roots = layers - 1;
    const uint64_t fixed =
        8 + 4 + 4 +                         // magic, revision, trace log2
        32 * 8 +                            // public input
        2 * DIGEST_LEN * 8 +                // trace and quotient roots
        4 + intermediate_roots * DIGEST_LEN * 8 +
        4 + TERMINAL_SIZE * 2 * 8 +
        4;                                  // query count

    uint64_t layer_bytes = 0;
    for (uint64_t layer = 0; layer < layers; ++layer) {
        layer_bytes += 40 + 64 * (uint64_t(lde_row_log2) - layer);
    }
    const uint64_t per_query =
        1040 + 64 * uint64_t(lde_row_log2) + layer_bytes;
    return fixed + QUERY_COUNT * per_query;
}

ScaleSpec scale_spec(uint32_t scale_log2) {
    if (scale_log2 < 20 || scale_log2 > 27) {
        throw std::runtime_error("Scale log2 must be in 20..27");
    }

    // Contract:
    //   Scale = total number of Goldilocks elements in the complete
    //           64-column post-LDE trace matrix.
    //   LDE rows   = Scale / 64.
    //   trace rows = Scale / (64 * 8).
    const uint64_t total = uint64_t(1) << scale_log2;
    const uint64_t lde_rows = total / AIR_WIDTH;
    const uint64_t trace_rows = lde_rows / BLOWUP;
    const uint32_t lde_row_log2 = scale_log2 - 6;
    const uint32_t trace_log2 = scale_log2 - 9;

    // Major arrays in the current correctness-first CPU prover:
    // trace rows       : 1.00 * Scale bytes
    // column trace copy: 1.00 * Scale bytes
    // column-major LDE : 8.00 * Scale bytes
    // row-major LDE    : 8.00 * Scale bytes
    // Fp2 quotient     : 0.25 * Scale bytes
    // This is only a lower bound; Merkle/FRI trees and temporaries are extra.
    const uint64_t core_lower_bound = (73 * total) / 4;

    return ScaleSpec{
        scale_log2,
        trace_log2,
        lde_row_log2,
        total,
        lde_rows,
        trace_rows,
        uint64_t(lde_row_log2 - 4),
        expected_proof_bytes_for_lde_log(lde_row_log2),
        total * sizeof(F),
        core_lower_bound
    };
}

void scale_csv_header() {
    std::cout
        << "implementation,scale_log2,total_lde_elements,lde_rows,trace_rows,"
           "fri_fold_rounds,proof_bytes,proof_fnv,core_lower_bound_bytes,"
           "prove_seconds,verify_seconds,prove_lde_elements_per_second,"
           "verify_proof_bytes_per_second,valid,wrong_statement_rejected,"
           "mutation_rejected,trailing_rejected\n";
}

void scale_contract_table() {
    std::cout
        << "scale_log2,total_lde_elements,committed_columns,lde_rows,"
           "lde_row_log2,trace_rows,trace_log2,trace_total_elements,blowup,"
           "trace_merkle_leaves,trace_merkle_height,fri_initial_fp2_elements,"
           "fri_fold_rounds,cpu_fri_committed_roots,"
           "fri_vectors_including_terminal,gpu_fri_root_count,"
           "fri_terminal_elements,query_count,proof_bytes,raw_trace_bytes,"
           "raw_lde_bytes,quotient_fp2_bytes,core_lower_bound_bytes,"
           "gpu_leaf_count,gpu_final_rows\n";
    for (uint32_t k = 20; k <= 27; ++k) {
        const auto s = scale_spec(k);
        const uint64_t trace_total_elements =
            s.trace_rows * uint64_t(AIR_WIDTH);
        const uint64_t fri_vectors = s.fri_fold_rounds + 1;
        std::cout
            << s.scale_log2 << ","
            << s.total_lde_elements << ","
            << AIR_WIDTH << ","
            << s.lde_rows << ","
            << s.lde_row_log2 << ","
            << s.trace_rows << ","
            << s.trace_log2 << ","
            << trace_total_elements << ","
            << BLOWUP << ","
            << s.lde_rows << ","
            << s.lde_row_log2 << ","
            << s.lde_rows << ","
            << s.fri_fold_rounds << ","
            << s.fri_fold_rounds << ","
            << fri_vectors << ","
            << fri_vectors << ","
            << TERMINAL_SIZE << ","
            << QUERY_COUNT << ","
            << s.proof_bytes << ","
            << s.total_lde_elements << ","
            << s.raw_lde_bytes << ","
            << s.total_lde_elements / 4 << ","
            << s.core_lower_bound_bytes << ","
            << s.lde_rows << ","
            << TERMINAL_SIZE << "\n";
    }
}

void scale_contract_test() {
    auto require=[](bool ok,const char* message){
        if(!ok)throw std::runtime_error(message);
    };
    require(expected_proof_bytes_for_lde_log(7)==177308,"proof size vector");

    uint64_t previous_proof_bytes=0;
    for(uint32_t k=20;k<=27;++k){
        const auto s=scale_spec(k);
        require(s.total_lde_elements==(uint64_t(1)<<k),"Scale total elements");
        require(s.lde_rows*AIR_WIDTH==s.total_lde_elements,"LDE row relation");
        require(s.trace_rows*BLOWUP==s.lde_rows,"blowup relation");
        require(s.trace_log2==k-9,"trace log relation");
        require(s.lde_row_log2==k-6,"LDE row log relation");
        require(s.fri_fold_rounds==k-10,"FRI fold relation");
        require(s.raw_lde_bytes==8*s.total_lde_elements,"raw LDE bytes");
        require(s.core_lower_bound_bytes==(73*s.total_lde_elements)/4,"core bytes");
        require(s.trace_rows*AIR_WIDTH==s.total_lde_elements/BLOWUP,"trace total relation");
        require(s.lde_rows==s.total_lde_elements/AIR_WIDTH,"Merkle leaf relation");
        require(s.lde_row_log2==uint32_t(std::countr_zero(s.lde_rows)),"Merkle height relation");
        require(s.fri_fold_rounds+1==uint64_t(s.lde_row_log2-3),"FRI vector relation");
        require(TERMINAL_SIZE==16 && QUERY_COUNT==64,"frozen proof parameters");
        require(s.proof_bytes>previous_proof_bytes,"proof size monotonic");
        require(root_of_unity(s.trace_log2).pow(s.trace_rows)==F(1),"trace root order");
        require(root_of_unity(s.lde_row_log2).pow(s.lde_rows)==F(1),"LDE root order");
        previous_proof_bytes=s.proof_bytes;
    }

    bool rejected_low=false,rejected_high=false;
    try{(void)scale_spec(19);}catch(...){rejected_low=true;}
    try{(void)scale_spec(28);}catch(...){rejected_high=true;}
    require(rejected_low && rejected_high,"Scale range rejection");
    std::cout<<"cpp scale contract: PASS\n";
}

void scale_run(uint32_t scale_log2,bool print_header) {
    const auto spec=scale_spec(scale_log2);
    using clock=std::chrono::steady_clock;

    Proof proof;
    const auto prove_begin=clock::now();
    {
        auto prover_data=prove(spec.trace_log2,7);
        proof=std::move(prover_data.proof);
    }
    const auto bytes=encode(proof);
    const auto prove_end=clock::now();

    if(bytes.size()!=spec.proof_bytes){
        throw std::runtime_error("proof byte count does not match Scale contract");
    }

    const auto expected=statement_for(spec.trace_log2,7);
    const auto verify_begin=clock::now();
    const bool valid=verify(bytes,expected);
    const auto verify_end=clock::now();

    auto wrong=expected;
    wrong.initial[0]+=F(1);
    const bool wrong_statement_rejected=!verify(bytes,wrong);

    auto mutated=bytes;
    mutated[mutated.size()/2]^=1;
    const bool mutation_rejected=!verify(mutated,expected);

    auto trailing=bytes;
    trailing.push_back(0);
    const bool trailing_rejected=!verify(trailing,expected);

    if(!valid || !wrong_statement_rejected || !mutation_rejected || !trailing_rejected){
        throw std::runtime_error("Scale proof correctness rejection check failed");
    }

    const double prove_seconds=
        std::chrono::duration<double>(prove_end-prove_begin).count();
    const double verify_seconds=
        std::chrono::duration<double>(verify_end-verify_begin).count();

    if(print_header)scale_csv_header();
    std::cout
        <<"cpp,"
        <<spec.scale_log2<<","
        <<spec.total_lde_elements<<","
        <<spec.lde_rows<<","
        <<spec.trace_rows<<","
        <<spec.fri_fold_rounds<<","
        <<bytes.size()<<","
        <<hx(fnv1a(bytes))<<","
        <<spec.core_lower_bound_bytes<<","
        <<std::setprecision(12)<<prove_seconds<<","
        <<std::setprecision(12)<<verify_seconds<<","
        <<std::setprecision(12)<<(double(spec.total_lde_elements)/prove_seconds)<<","
        <<std::setprecision(12)<<(double(bytes.size())/verify_seconds)<<","
        <<(valid?1:0)<<","
        <<(wrong_statement_rejected?1:0)<<","
        <<(mutation_rejected?1:0)<<","
        <<(trailing_rejected?1:0)
        <<"\n";
}

void scale_matrix(uint32_t first,uint32_t last) {
    if(first<20 || last>27 || first>last){
        throw std::runtime_error("scale-matrix range must be within 20..27");
    }
    scale_csv_header();
    for(uint32_t k=first;k<=last;++k){
        scale_run(k,false);
    }
}

uint64_t fnv1a(const std::vector<uint8_t>& b){
    uint64_t h=1469598103934665603ULL;for(uint8_t x:b){h^=x;h*=1099511628211ULL;}return h;
}
std::string hx(uint64_t x){std::ostringstream s;s<<std::hex<<std::setw(16)<<std::setfill('0')<<x;return s.str();}

void self_test(){
    auto require=[](bool x,const char* m){if(!x)throw std::runtime_error(m);};
    F a(P-1),b(2); require((a+b)==F(1),"field add");
    require(F(1234567)*F(1234567).inv()==F(1),"field inverse");
    E e(F(11),F(9));require(e*e.inv()==E(F(1)),"ext inverse");
    State z{};permute(z);
    require(z[0].v==0x18bfb581dfb0a9a9ULL && z[11].v==0x1de9b4ffa41e4d89ULL,"poseidon vector");
    std::vector<F> seq(12);for(size_t i=0;i<12;i++)seq[i]=F(i);
    auto h=hash_fields(seq,Domain::Hash);require(h[0].v==0x5f068621cee96577ULL,"hash vector");

    auto expected=statement_for(4,3);
    auto t=make_trace(16,expected.initial);
    for(size_t i=0;i+1<t.size();i++)require(valid_transition(t[i],t[i+1]),"air");
    std::vector<F> x(16);
    for(size_t i=0;i<x.size();i++)x[i]=F(i*i+7);
    auto y=x;ntt(y,false);ntt(y,true);require(x==y,"ntt");

    auto pd=prove(4,3);
    auto bytes=encode(pd.proof);
    require(pd.proof.pub==expected,"prover statement");
    require(verify(bytes,expected),"proof verify");

    auto wrong_statement=expected;
    wrong_statement.initial[0]+=F(1);
    require(!verify(bytes,wrong_statement),"external initial statement reject");
    wrong_statement=expected;
    wrong_statement.final_acc[0]+=F(1);
    require(!verify(bytes,wrong_statement),"external final statement reject");

    auto public_bad=bytes;
    public_bad[16]^=1;
    require(!verify(public_bad,expected),"encoded public input reject");

    auto bad_proof=pd.proof;
    bad_proof.trace_root[0]+=F(1);
    require(!verify(encode(bad_proof),expected),"trace root reject");

    bad_proof=pd.proof;
    bad_proof.queries[0].cur.row[0]+=F(1);
    require(!verify(encode(bad_proof),expected),"trace opening reject");

    bad_proof=pd.proof;
    bad_proof.terminal[0].a+=F(1);
    require(!verify(encode(bad_proof),expected),"fri terminal reject");

    auto bad=bytes;
    bad[bad.size()/2]^=1;
    require(!verify(bad,expected),"mutation reject");
    bad=bytes;bad.push_back(0);
    require(!verify(bad,expected),"trailing reject");
    std::cout<<"cpp correctness: PASS\n";
}
void vectors(){
    State z{};permute(z);
    std::vector<F> seq(12);for(size_t i=0;i<12;i++)seq[i]=F(i);
    auto h=hash_fields(seq,Domain::Hash);
    auto pd=prove(4,3);auto bytes=encode(pd.proof);
    std::cout<<"poseidon_zero_0="<<hx(z[0].v)<<"\n";
    std::cout<<"poseidon_zero_11="<<hx(z[11].v)<<"\n";
    std::cout<<"hash_seq_0="<<hx(h[0].v)<<"\n";
    std::cout<<"proof_size="<<bytes.size()<<"\n";
    std::cout<<"proof_fnv="<<hx(fnv1a(bytes))<<"\n";
}
void bench(uint32_t log_n){
    if(log_n<4||log_n>24)throw std::runtime_error("bench log_n 4..24");
    using clock=std::chrono::steady_clock;
    volatile uint64_t sink=0;
    const size_t muls=2000000;
    F x(3),y(5);
    auto a=clock::now();for(size_t i=0;i<muls;i++){x=x*y+F(i);sink^=x.v;}auto b=clock::now();
    double sec=std::chrono::duration<double>(b-a).count();
    std::cout<<"cpp,field_mul_add,"<<muls<<","<<sec<<","<<(muls/sec)<<"\n";
    State s{};const size_t perms=200;
    a=clock::now();for(size_t i=0;i<perms;i++){s[0]+=F(i);permute(s);sink^=s[0].v;}b=clock::now();
    sec=std::chrono::duration<double>(b-a).count();
    std::cout<<"cpp,poseidon2_permute,"<<perms<<","<<sec<<","<<(perms/sec)<<"\n";
    a=clock::now();auto p=prove(log_n,7);auto bytes=encode(p.proof);b=clock::now();
    sec=std::chrono::duration<double>(b-a).count();
    std::cout<<"cpp,stark_prove,"<<(size_t(1)<<log_n)<<","<<sec<<","<<((size_t(1)<<log_n)/sec)<<"\n";
    auto expected=statement_for(log_n,7);
    a=clock::now();bool ok=verify(bytes,expected);b=clock::now();if(!ok)throw std::runtime_error("bench proof");
    sec=std::chrono::duration<double>(b-a).count();
    std::cout<<"cpp,stark_verify,"<<bytes.size()<<","<<sec<<","<<(bytes.size()/sec)<<"\n";
    if(sink==0xdeadbeef)std::cerr<<"";
}



void trace_file(uint32_t scale_log2,const std::string& path){
    const auto spec=scale_spec(scale_log2);
    auto pub=statement_for(spec.trace_log2,7);
    auto trace=make_trace((size_t)spec.trace_rows,pub.initial);
    std::ofstream out(path,std::ios::binary);
    if(!out)throw std::runtime_error("cannot create trace file");
    out.write("QMT64T01",8);
    auto w32=[&](uint32_t x){for(int i=0;i<4;++i){char c=(char)(x>>(8*i));out.write(&c,1);}};
    auto w64=[&](uint64_t x){for(int i=0;i<8;++i){char c=(char)(x>>(8*i));out.write(&c,1);}};
    w32(1);w32(scale_log2);w64(spec.trace_rows);w32((uint32_t)AIR_WIDTH);w32(0);
    for(const auto& row:trace)for(F x:row)w64(x.v);
    out.close();if(!out)throw std::runtime_error("trace file write failed");
    std::cout<<"status=PASS\nformat=QMT64T01\nscale_log2="<<scale_log2
             <<"\ntrace_rows="<<spec.trace_rows<<"\ncolumns="<<AIR_WIDTH
             <<"\ntrace_file="<<path<<"\n";
}

void proof_file(uint32_t scale_log2,const std::string& path){
    const auto spec=scale_spec(scale_log2);
    auto pd=prove(spec.trace_log2,7);
    auto bytes=encode(pd.proof);
    auto expected=statement_for(spec.trace_log2,7);
    if(bytes.size()!=spec.proof_bytes || !verify(bytes,expected)){
        throw std::runtime_error("proof-file canonical verification failed");
    }
    std::ofstream out(path,std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()),(std::streamsize)bytes.size());
    out.close();
    if(!out)throw std::runtime_error("cannot write proof file");
    std::cout<<"status=PASS\nimplementation=cpp\nproof_format=QMG64P01\nscale_log2="<<scale_log2
             <<"\ntrace_log2="<<spec.trace_log2<<"\nlde_rows="<<spec.lde_rows
             <<"\nfri_fold_rounds="<<spec.fri_fold_rounds<<"\nquery_count="<<QUERY_COUNT
             <<"\nterminal_elements="<<TERMINAL_SIZE<<"\nproof_bytes="<<bytes.size()
             <<"\nproof_fnv="<<hx(fnv1a(bytes))<<"\ntrace_root=";
    for(size_t i=0;i<DIGEST_LEN;++i){if(i)std::cout<<";";std::cout<<"0x"<<hx(pd.proof.trace_root[i].v);}
    std::cout<<"\nproof_file="<<path<<"\nverifier=PASS\n";
}

void verify_file(uint32_t scale_log2,const std::string& path){
    const auto spec=scale_spec(scale_log2);
    std::ifstream in(path,std::ios::binary);
    if(!in)throw std::runtime_error("cannot open proof file");
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),{});
    auto expected=statement_for(spec.trace_log2,7);
    if(!verify(bytes,expected))throw std::runtime_error("proof rejected");
    std::cout<<"status=PASS\nimplementation=cpp_verifier\nscale_log2="<<scale_log2
             <<"\nproof_bytes="<<bytes.size()<<"\nproof_fnv="<<hx(fnv1a(bytes))
             <<"\nverifier=PASS\n";
}

} // namespace qm

int main(int argc,char** argv){
    try{
        std::string cmd=argc>1?argv[1]:"test";
        if(cmd=="test")qm::self_test();
        else if(cmd=="vectors")qm::vectors();
        else if(cmd=="scale-contract")qm::scale_contract_test();
        else if(cmd=="scale-table")qm::scale_contract_table();
        else if(cmd=="scale-run")qm::scale_run(argc>2?(uint32_t)std::stoul(argv[2]):20,true);
        else if(cmd=="scale-matrix")qm::scale_matrix(
            argc>2?(uint32_t)std::stoul(argv[2]):20,
            argc>3?(uint32_t)std::stoul(argv[3]):27
        );
        else if(cmd=="bench")qm::bench(argc>2?(uint32_t)std::stoul(argv[2]):7);
        else if(cmd=="proof-file")qm::proof_file(argc>2?(uint32_t)std::stoul(argv[2]):20,argc>3?argv[3]:"cpp-proof.qmg64p01");
        else if(cmd=="verify-file")qm::verify_file(argc>2?(uint32_t)std::stoul(argv[2]):20,argc>3?argv[3]:"cpp-proof.qmg64p01");
        else if(cmd=="trace-file")qm::trace_file(argc>2?(uint32_t)std::stoul(argv[2]):20,argc>3?argv[3]:"cpp-trace.qmt64t01");
        else throw std::runtime_error(
            "usage: test|vectors|scale-contract|scale-table|scale-run K|"
            "scale-matrix [K_MIN] [K_MAX]|bench [trace_log2]|proof-file K PATH|verify-file K PATH|trace-file K PATH"
        );
        return 0;
    }catch(const std::exception& e){std::cerr<<"ERROR: "<<e.what()<<"\n";return 1;}
}
