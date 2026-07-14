// QINGMING-STARK-G64 single-file Rust CPU reference.
// SPDX-License-Identifier: Apache-2.0
//
// Build directly:
//   rustc -O qingming_stark_g64.rs -o qingming_stark_g64_rs
//
// Commands:
//   qingming_stark_g64_rs test
//   qingming_stark_g64_rs vectors
//   qingming_stark_g64_rs scale-contract
//   qingming_stark_g64_rs scale-table
//   qingming_stark_g64_rs scale-run K
//   qingming_stark_g64_rs scale-matrix [K_MIN] [K_MAX]
//   qingming_stark_g64_rs bench [trace_log2]

use std::convert::TryInto;
use std::env;
use std::fs;
use std::ops::{Add, AddAssign, Div, Mul, MulAssign, Sub};
use std::time::Instant;

const P:u64=0xffff_ffff_0000_0001;
const GENERATOR:u64=7;
const WIDTH:usize=12;
const RATE:usize=8;
const DIGEST_LEN:usize=4;
const AIR_WIDTH:usize=64;
const BLOWUP:usize=8;
const QUERY_COUNT:usize=64;
const TERMINAL_SIZE:usize=16;
const PARAM_FP:u64=0xad77_784b_434b_b34c;
const VECTOR_FP:u64=0xffdf_9225_a183_4ebc;

#[derive(Copy,Clone,Default,PartialEq,Eq,Debug)]
struct F(u64);
impl F {
    fn new(x:u64)->Self { Self(if x>=P{x-P}else{x}) }
    fn canonical(x:u64)->Option<Self>{if x<P{Some(Self(x))}else{None}}
    fn pow(self,mut e:u64)->Self{let mut b=self;let mut r=F::new(1);while e!=0{if e&1!=0{r*=b;}b*=b;e>>=1;}r}
    fn inv(self)->Self{assert!(self.0!=0,"inverse of zero");self.pow(P-2)}
}
impl Add for F{type Output=F;fn add(self,o:F)->F{F::new(((self.0 as u128+o.0 as u128)%(P as u128))as u64)}}
impl Sub for F{type Output=F;fn sub(self,o:F)->F{if self.0>=o.0{F(self.0-o.0)}else{F(P-(o.0-self.0))}}}
impl Mul for F{type Output=F;fn mul(self,o:F)->F{F::new(((self.0 as u128*o.0 as u128)%(P as u128))as u64)}}
impl Div for F{type Output=F;fn div(self,o:F)->F{self*o.inv()}}
impl AddAssign for F{fn add_assign(&mut self,o:F){*self=*self+o;}}
impl MulAssign for F{fn mul_assign(&mut self,o:F){*self=*self*o;}}

#[derive(Copy,Clone,Default,PartialEq,Eq,Debug)]
struct E{a:F,b:F}
impl E{fn new(a:F,b:F)->Self{Self{a,b}} fn from_f(x:F)->Self{Self{a:x,b:F::default()}} fn inv(self)->Self{let ni=(self.a*self.a-F::new(7)*(self.b*self.b)).inv();Self::new(self.a*ni,F::default()-self.b*ni)}}
impl Add for E{type Output=E;fn add(self,o:E)->E{E::new(self.a+o.a,self.b+o.b)}}
impl Sub for E{type Output=E;fn sub(self,o:E)->E{E::new(self.a-o.a,self.b-o.b)}}
impl Mul for E{type Output=E;fn mul(self,o:E)->E{E::new(self.a*o.a+F::new(7)*(self.b*o.b),self.a*o.b+self.b*o.a)}}
impl Mul<F> for E{type Output=E;fn mul(self,o:F)->E{E::new(self.a*o,self.b*o)}}
impl AddAssign for E{fn add_assign(&mut self,o:E){*self=*self+o;}}
impl MulAssign for E{fn mul_assign(&mut self,o:E){*self=*self*o;}}

type Digest=[F;DIGEST_LEN];
type State=[F;WIDTH];
type Row=[F;AIR_WIDTH];

#[derive(Copy,Clone)]
enum Domain{Hash=1,Leaf=2,Node=3,Fri=4,Transcript=5}

const RC_EXT:[u64;96]=[
    0x0b076c9815e150a0u64, 0xb7cf86203d363b0au64, 0xde03f4cb664f1bc6u64, 0x74943c07ec7efa51u64,
    0x63fbc38b42e086cbu64, 0x22eb9f8c147fb7a0u64, 0x51d15b40772ee69du64, 0x6ef868441cfd681au64,
    0xd0defa5b34606ca7u64, 0x8576810cf3404b1du64, 0x6f0aa8bd2408c611u64, 0x226c2c863a3f8d19u64,
    0x21c53f5ae2809078u64, 0xc8831bc847540d42u64, 0x4bd92fc616521496u64, 0x14be24c87353c837u64,
    0x45df5e726aadeb6bu64, 0x27dc81ac2dcd4336u64, 0xffcf1d29b3a89ad8u64, 0x972fc8a5923b9e23u64,
    0xbf8aec8e44580cf4u64, 0x6d06be20765eed44u64, 0x372237c13f745e49u64, 0xcaafd3713802689du64,
    0x54ddfadcde987ad7u64, 0x8ccb575f8a5133ffu64, 0x7b1db7bc8a67d165u64, 0xc966242795cce80eu64,
    0xfe2342bf74fc16e3u64, 0x1d65ca66c5e35627u64, 0xc2b01aef77fa4021u64, 0x45c9d816750eda7du64,
    0x9a546db1904b9d38u64, 0x40d367bf6b367c5du64, 0x43428a669040cafdu64, 0xa6832107c92e41edu64,
    0xc99c50f22dfd27a1u64, 0x2e17386f90bf5580u64, 0x12d391accb7b790au64, 0xebd5c9c1667b6303u64,
    0x10a4cf9430f01a86u64, 0x089ba3b2605a3a39u64, 0x0e5c2d8405573d2du64, 0xf34465d2a47a768du64,
    0xe86e9adfd7e18db8u64, 0xf4aed4f4a91f944eu64, 0xb6aa6500c788f221u64, 0x72a39df30b1cbf43u64,
    0x4f106841a5afb226u64, 0x6531cf4716443cb0u64, 0x0c1361de5a72f7aau64, 0xaa5d699563835b24u64,
    0xbefb4e4682f823acu64, 0xbf79ae73ee3b4759u64, 0xea50f3230ab83ff7u64, 0x9016d5f3d6bfbd5cu64,
    0xaa2aecb411021ae4u64, 0x95a3119d1fb2182bu64, 0x4e14282eca3bfad7u64, 0x1c7784d0d72cfb4du64,
    0xd9c670470bda32a7u64, 0x8ae140eb11658f91u64, 0x7dfd2c7f25e304c8u64, 0x09e528364ba06100u64,
    0x498050c8a97ce032u64, 0x27a7ea1ab98b243cu64, 0xdff63ffe44fd2952u64, 0xf6eea4c587dd44cdu64,
    0xf19ebf6b5a07b8a0u64, 0x33029c811d2b7151u64, 0x007748756eae3bf9u64, 0x33256d1225d2db57u64,
    0x00f0367194f6691cu64, 0x714dc8081a8d0d6cu64, 0x5736c450d9da45fau64, 0x2450c7ba79945a75u64,
    0x552a068235886ce3u64, 0x72d000f0d5208986u64, 0x27991057cd3a021cu64, 0xcf61be5d2aa4e84au64,
    0xa4c2247134e84361u64, 0xd9517f33121cf36du64, 0x382d3738386464b8u64, 0x3af4ee1d9630925au64,
    0x21f22cb6d3a94971u64, 0x38f452094e53421du64, 0x83d7231efa6a15b0u64, 0xce22e6f5b256459du64,
    0x517f83511cded60fu64, 0x718a62786dd336b1u64, 0x9c1bbf135a61bdb2u64, 0x2983f8cb26ed7c14u64,
    0x820f6a56259282d8u64, 0x4c6c766b6338a1f0u64, 0x83d9955a505f73fau64, 0x6edd716b1400cee5u64
];
const RC_INT:[u64;22]=[
    0x326defdb73b5a74fu64, 0x12ff33e7d89a7f1bu64, 0xd9b0c5515934a971u64, 0xe12732a314f7346bu64,
    0x02cf88aeae0c5d32u64, 0x8a1712dffbd830b3u64, 0xc48aa0fc6eb801bau64, 0x5a978bb08fa763d1u64,
    0x106cf3e0a8364b5eu64, 0x5d95fc48ac1f29adu64, 0x2c975dd2e229da68u64, 0x40cbaf88147700efu64,
    0xc52ad03f2a33a991u64, 0x1701a33c70808721u64, 0xeb44ee9881504e1au64, 0xcc7d4368e3f043bdu64,
    0xa5ccd326e46f7f39u64, 0x8136de66b6637aa5u64, 0x33d3db2cd8ca8a7du64, 0x5d2ffd093df99e7au64,
    0xe2374063fefecd9fu64, 0x5369d92f39ed6975u64
];
const EXT_MAT:[u64;144]=[
    0x1249249236db6db7u64, 0xeeeeeeee00000001u64, 0xefffffff10000001u64, 0xf0f0f0f000000001u64,
    0x9c71c71bd5555556u64, 0x9435e50ce50d7944u64, 0xf333333240000001u64, 0x6186186124924925u64,
    0x3a2e8ba2ae8ba2e9u64, 0x9bd37a6eb21642c9u64, 0xf555555460000001u64, 0xc28f5c2833333334u64,
    0xeeeeeeee00000001u64, 0xefffffff10000001u64, 0xf0f0f0f000000001u64, 0x9c71c71bd5555556u64,
    0x9435e50ce50d7944u64, 0xf333333240000001u64, 0x6186186124924925u64, 0x3a2e8ba2ae8ba2e9u64,
    0x9bd37a6eb21642c9u64, 0xf555555460000001u64, 0xc28f5c2833333334u64, 0xcec4ec4df6276277u64,
    0xefffffff10000001u64, 0xf0f0f0f000000001u64, 0x9c71c71bd5555556u64, 0x9435e50ce50d7944u64,
    0xf333333240000001u64, 0x6186186124924925u64, 0x3a2e8ba2ae8ba2e9u64, 0x9bd37a6eb21642c9u64,
    0xf555555460000001u64, 0xc28f5c2833333334u64, 0xcec4ec4df6276277u64, 0xbda12f678e38e38fu64,
    0xf0f0f0f000000001u64, 0x9c71c71bd5555556u64, 0x9435e50ce50d7944u64, 0xf333333240000001u64,
    0x6186186124924925u64, 0x3a2e8ba2ae8ba2e9u64, 0x9bd37a6eb21642c9u64, 0xf555555460000001u64,
    0xc28f5c2833333334u64, 0xcec4ec4df6276277u64, 0xbda12f678e38e38fu64, 0x892492489b6db6dcu64,
    0x9c71c71bd5555556u64, 0x9435e50ce50d7944u64, 0xf333333240000001u64, 0x6186186124924925u64,
    0x3a2e8ba2ae8ba2e9u64, 0x9bd37a6eb21642c9u64, 0xf555555460000001u64, 0xc28f5c2833333334u64,
    0xcec4ec4df6276277u64, 0xbda12f678e38e38fu64, 0x892492489b6db6dcu64, 0x8d3dcb08469ee585u64,
    0x9435e50ce50d7944u64, 0xf333333240000001u64, 0x6186186124924925u64, 0x3a2e8ba2ae8ba2e9u64,
    0x9bd37a6eb21642c9u64, 0xf555555460000001u64, 0xc28f5c2833333334u64, 0xcec4ec4df6276277u64,
    0xbda12f678e38e38fu64, 0x892492489b6db6dcu64, 0x8d3dcb08469ee585u64, 0xf777777680000001u64,
    0xf333333240000001u64, 0x6186186124924925u64, 0x3a2e8ba2ae8ba2e9u64, 0x9bd37a6eb21642c9u64,
    0xf555555460000001u64, 0xc28f5c2833333334u64, 0xcec4ec4df6276277u64, 0xbda12f678e38e38fu64,
    0x892492489b6db6dcu64, 0x8d3dcb08469ee585u64, 0xf777777680000001u64, 0x9ce739cdd6b5ad6cu64,
    0x6186186124924925u64, 0x3a2e8ba2ae8ba2e9u64, 0x9bd37a6eb21642c9u64, 0xf555555460000001u64,
    0xc28f5c2833333334u64, 0xcec4ec4df6276277u64, 0xbda12f678e38e38fu64, 0x892492489b6db6dcu64,
    0x8d3dcb08469ee585u64, 0xf777777680000001u64, 0x9ce739cdd6b5ad6cu64, 0xf7ffffff08000001u64,
    0x3a2e8ba2ae8ba2e9u64, 0x9bd37a6eb21642c9u64, 0xf555555460000001u64, 0xc28f5c2833333334u64,
    0xcec4ec4df6276277u64, 0xbda12f678e38e38fu64, 0x892492489b6db6dcu64, 0x8d3dcb08469ee585u64,
    0xf777777680000001u64, 0x9ce739cdd6b5ad6cu64, 0xf7ffffff08000001u64, 0x26c9b26c745d1746u64,
    0x9bd37a6eb21642c9u64, 0xf555555460000001u64, 0xc28f5c2833333334u64, 0xcec4ec4df6276277u64,
    0xbda12f678e38e38fu64, 0x892492489b6db6dcu64, 0x8d3dcb08469ee585u64, 0xf777777680000001u64,
    0x9ce739cdd6b5ad6cu64, 0xf7ffffff08000001u64, 0x26c9b26c745d1746u64, 0xf878787780000001u64,
    0xf555555460000001u64, 0xc28f5c2833333334u64, 0xcec4ec4df6276277u64, 0xbda12f678e38e38fu64,
    0x892492489b6db6dcu64, 0x8d3dcb08469ee585u64, 0xf777777680000001u64, 0x9ce739cdd6b5ad6cu64,
    0xf7ffffff08000001u64, 0x26c9b26c745d1746u64, 0xf878787780000001u64, 0xd41d41d34924924au64,
    0xc28f5c2833333334u64, 0xcec4ec4df6276277u64, 0xbda12f678e38e38fu64, 0x892492489b6db6dcu64,
    0x8d3dcb08469ee585u64, 0xf777777680000001u64, 0x9ce739cdd6b5ad6cu64, 0xf7ffffff08000001u64,
    0x26c9b26c745d1746u64, 0xf878787780000001u64, 0xd41d41d34924924au64, 0x4e38e38deaaaaaabu64
];
const INT_DIAG:[u64;12]=[
    0x45de1a790b7ca367u64, 0x3b7bc0355c554c31u64, 0x2ea7837f64608ed1u64, 0xec08c0bb4ac8d7b6u64,
    0x92f739c73a48c00au64, 0x9a27c421c857b6deu64, 0x9053430cf38c54e8u64, 0x676235d216f0867au64,
    0x8d00bdc05545249au64, 0x27b62f800265c059u64, 0xf6ba33681d8dabccu64, 0x401e54e3de16d979u64
];
const DOMAIN_TAGS:[u64;6]=[
    0xd2fb5fa99c55b924u64, 0x02d5e8bc7c95bb78u64, 0xd49a71f4a1e84acau64, 0x8246b91cbc96cbc1u64,
    0x01ef068df61d210bu64, 0x5cab39dee3685311u64
];

fn pow7(x:F)->F{let x2=x*x;let x3=x2*x;let x4=x2*x2;x3*x4}
fn external_mix(s:&mut State){let mut o=[F::default();WIDTH];for r in 0..WIDTH{let mut a=F::default();for c in 0..WIDTH{a+=F::new(EXT_MAT[r*WIDTH+c])*s[c];}o[r]=a;}*s=o;}
fn internal_mix(s:&mut State){let mut total=F::default();for x in s.iter(){total+=*x;}let mut o=[F::default();WIDTH];for i in 0..WIDTH{o[i]=total+F::new(INT_DIAG[i])*s[i];}*s=o;}
fn permute(s:&mut State){
    external_mix(s);
    for r in 0..4{for i in 0..WIDTH{s[i]=pow7(s[i]+F::new(RC_EXT[r*WIDTH+i]));}external_mix(s);}
    for r in 0..22{s[0]=pow7(s[0]+F::new(RC_INT[r]));internal_mix(s);}
    for r in 4..8{for i in 0..WIDTH{s[i]=pow7(s[i]+F::new(RC_EXT[r*WIDTH+i]));}external_mix(s);}
}
fn hash_fields(vals:&[F],d:Domain)->Digest{
    let mut s=[F::default();WIDTH];s[RATE]=F::new(DOMAIN_TAGS[d as usize]);
    if vals.is_empty(){s[0]+=F::new(1);permute(&mut s);}else{
        let mut off=0;
        while off<vals.len(){let n=RATE.min(vals.len()-off);for i in 0..n{s[i]+=vals[off+i];}if n<RATE{s[n]+=F::new(1);}permute(&mut s);off+=n;}
    }
    [s[0],s[1],s[2],s[3]]
}
fn leaf_hash(idx:u64,vals:&[F])->Digest{let mut x=Vec::with_capacity(vals.len()+1);x.push(F::new(idx));x.extend_from_slice(vals);hash_fields(&x,Domain::Leaf)}
fn node_hash(l:Digest,r:Digest)->Digest{let mut x=[F::default();8];x[..4].copy_from_slice(&l);x[4..].copy_from_slice(&r);hash_fields(&x,Domain::Node)}

struct Transcript{s:State,pos:usize}
impl Transcript{
    fn new()->Self{let mut t=Self{s:[F::default();WIDTH],pos:0};t.s[RATE]=F::new(DOMAIN_TAGS[Domain::Transcript as usize]);t.s[0]=F::new(PARAM_FP);t.s[1]=F::new(VECTOR_FP);t.cycle();t}
    fn cycle(&mut self){permute(&mut self.s);self.pos=0;}
    fn absorb(&mut self,d:Domain,vals:&[F]){
        if self.pos==RATE{self.cycle();}self.s[self.pos]+=F::new(DOMAIN_TAGS[d as usize]);self.pos+=1;
        for x in vals{if self.pos==RATE{self.cycle();}self.s[self.pos]+=*x;self.pos+=1;}
        if self.pos==RATE{self.cycle();}self.s[self.pos]+=F::new(1);self.pos+=1;self.cycle();
    }
    fn absorb_digest(&mut self,d:Domain,x:Digest){self.absorb(d,&x);}
    fn challenge(&mut self,d:Domain)->F{let label=[F::new(DOMAIN_TAGS[d as usize])];self.absorb(Domain::Transcript,&label);let r=self.s[0];self.cycle();r}
    fn challenge_ext(&mut self)->E{E::new(self.challenge(Domain::Transcript),self.challenge(Domain::Transcript))}
    fn challenge_index(&mut self,n:u32)->u32{assert!(n!=0&&n.is_power_of_two());let limit=(P/(n as u64))*(n as u64);loop{let x=self.challenge(Domain::Transcript).0;if x<limit{return (x%(n as u64))as u32;}}}
}

fn root_of_unity(log_n:u32)->F{assert!(log_n<=32);let r=F::new(GENERATOR).pow((P-1)>>log_n);assert_eq!(r.pow(1u64<<log_n),F::new(1));if log_n!=0{assert_ne!(r.pow(1u64<<(log_n-1)),F::new(1));}r}
trait Ring:Copy+Default+Add<Output=Self>+Sub<Output=Self>{fn mul_base(self,x:F)->Self;}
impl Ring for F{fn mul_base(self,x:F)->Self{self*x}}
impl Ring for E{fn mul_base(self,x:F)->Self{self*x}}
fn ntt<T:Ring>(a:&mut [T],inverse:bool){
    let n=a.len();assert!(n!=0&&n.is_power_of_two());let lg=n.trailing_zeros();
    let mut j=0usize;
    for i in 1..n{let mut bit=n>>1;while j&bit!=0{j^=bit;bit>>=1;}j^=bit;if i<j{a.swap(i,j);}}
    let mut root=root_of_unity(lg);if inverse{root=root.inv();}
    let mut len=2;while len<=n{let wlen=root.pow((n/len)as u64);let mut i=0;while i<n{let mut w=F::new(1);for k in 0..len/2{let u=a[i+k];let v=a[i+k+len/2].mul_base(w);a[i+k]=u+v;a[i+k+len/2]=u-v;w*=wlen;}i+=len;}len<<=1;}
    if inverse{let ni=F::new(n as u64).inv();for x in a.iter_mut(){*x=x.mul_base(ni);}}
}
fn lde<T:Ring>(evals:&[T],blowup:usize,shift:F)->Vec<T>{let mut c=evals.to_vec();ntt(&mut c,true);let n=c.len();c.resize(n*blowup,T::default());let mut p=F::new(1);for x in c[..n].iter_mut(){*x=x.mul_base(p);p*=shift;}ntt(&mut c,false);c}
fn interpolate_coset<T:Ring>(evals:&[T],offset:F)->Vec<T>{let mut c=evals.to_vec();ntt(&mut c,true);let inv=offset.inv();let mut p=F::new(1);for x in c.iter_mut(){*x=x.mul_base(p);p*=inv;}c}

fn lane_const(j:usize)->F{F::new(0x9e37_79b9_7f4a_7c15u64+j as u64)}
fn initial_row(init:&[F;16])->Row{let mut r=[F::default();AIR_WIDTH];for j in 0..16{r[j]=init[j];r[16+j]=F::default();r[32+j]=init[j]*init[(j+1)%16];r[48+j]=init[j]*init[j];}r}
fn next_row(c:&Row)->Row{let mut n=[F::default();AIR_WIDTH];for j in 0..16{let x=c[j];let y=c[(j+1)%16];let m=c[32+j];let h=c[48+j];n[j]=lane_const(j)+x+F::new(3)*y+F::new(5)*h+F::new(7)*m;n[16+j]=c[16+j]+m;}for j in 0..16{n[32+j]=n[j]*n[(j+1)%16];n[48+j]=n[j]*n[j];}n}
fn make_trace(n:usize,init:&[F;16])->Vec<Row>{assert!(n>=2&&n.is_power_of_two());let mut t=vec![[F::default();AIR_WIDTH];n];t[0]=initial_row(init);for i in 1..n{t[i]=next_row(&t[i-1]);}t}
fn valid_transition(c:&Row,n:&Row)->bool{for j in 0..16{let x=c[j];let y=c[(j+1)%16];let m=c[32+j];let h=c[48+j];if m-x*y!=F::default()||h-x*x!=F::default(){return false;}if n[16+j]-c[16+j]-m!=F::default(){return false;}if n[j]-lane_const(j)-x-F::new(3)*y-F::new(5)*h-F::new(7)*m!=F::default(){return false;}}true}

#[derive(Clone)]
struct Merkle{levels:Vec<Vec<Digest>>}
impl Merkle{
    fn build(leaves:&[Vec<F>])->Self{assert!(!leaves.is_empty()&&leaves.len().is_power_of_two());let mut levels=vec![leaves.iter().enumerate().map(|(i,x)|leaf_hash(i as u64,x)).collect::<Vec<_>>()];while levels.last().unwrap().len()>1{let p=levels.last().unwrap();let mut q=Vec::with_capacity(p.len()/2);for i in 0..p.len()/2{q.push(node_hash(p[2*i],p[2*i+1]));}levels.push(q);}Self{levels}}
    fn root(&self)->Digest{self.levels.last().unwrap()[0]}
    fn path(&self,mut idx:usize)->Vec<Digest>{let mut p=Vec::with_capacity(self.levels.len()-1);for l in 0..self.levels.len()-1{p.push(self.levels[l][idx^1]);idx>>=1;}p}
}
fn verify_path(mut idx:u32,vals:&[F],path:&[Digest],root:Digest)->bool{let mut h=leaf_hash(idx as u64,vals);for sib in path{h=if idx&1!=0{node_hash(*sib,h)}else{node_hash(h,*sib)};idx>>=1;}h==root}
fn e_leaves(x:&[E])->Vec<Vec<F>>{x.iter().map(|v|vec![v.a,v.b]).collect()}

#[derive(Clone,PartialEq,Eq)]
struct PublicInput{initial:[F;16],final_acc:[F;16]}
fn public_digest(log_n:u32,input:&PublicInput)->Digest{let mut x=Vec::with_capacity(33);x.push(F::new(log_n as u64));x.extend_from_slice(&input.initial);x.extend_from_slice(&input.final_acc);hash_fields(&x,Domain::Hash)}
fn composition_at(z:F,c:&Row,n:&Row,pub_in:&PublicInput,alpha:E,trace_n:usize,last:F)->E{
    let ztrans=(z.pow(trace_n as u64)-F::new(1))/(z-last);let inv_trans=ztrans.inv();let inv_init=(z-F::new(1)).inv();let inv_final=(z-last).inv();
    let mut acc=E::default();let mut power=E::from_f(F::new(1));
    let mut add=|value:F,invz:F|{acc+=power*E::from_f(value*invz);power*=alpha;};
    for j in 0..16{let x=c[j];let y=c[(j+1)%16];let m=c[32+j];let h=c[48+j];add(m-x*y,inv_trans);add(h-x*x,inv_trans);add(n[16+j]-c[16+j]-m,inv_trans);add(n[j]-lane_const(j)-x-F::new(3)*y-F::new(5)*h-F::new(7)*m,inv_trans);}
    for j in 0..16{add(c[j]-pub_in.initial[j],inv_init);}
    for j in 0..16{add(c[16+j],inv_init);}
    for j in 0..16{add(c[16+j]-pub_in.final_acc[j],inv_final);}
    acc
}

#[derive(Clone)]
struct TraceOpen{row:Row,path:Vec<Digest>}
impl Default for TraceOpen{
    fn default()->Self{
        Self{row:[F::default();AIR_WIDTH],path:Vec::new()}
    }
}
#[derive(Clone,Default)]
struct FriPair{lo:E,hi:E,plo:Vec<Digest>,phi:Vec<Digest>}
#[derive(Clone,Default)]
struct Query{idx:u32,cur:TraceOpen,nxt:TraceOpen,layers:Vec<FriPair>}
#[derive(Clone)]
struct Proof{log_n:u32,pub_in:PublicInput,trace_root:Digest,quotient_root:Digest,intermediate_roots:Vec<Digest>,terminal:Vec<E>,queries:Vec<Query>}

fn put32(b:&mut Vec<u8>,x:u32){b.extend_from_slice(&x.to_le_bytes());}
fn put64(b:&mut Vec<u8>,x:u64){b.extend_from_slice(&x.to_le_bytes());}
fn putf(b:&mut Vec<u8>,x:F){put64(b,x.0);}
fn putd(b:&mut Vec<u8>,d:Digest){for x in d{putf(b,x);}}
fn encode(p:&Proof)->Vec<u8>{
    let mut b=Vec::new();b.extend_from_slice(b"QMG64P01");put32(&mut b,1);put32(&mut b,p.log_n);
    for x in p.pub_in.initial{putf(&mut b,x);}for x in p.pub_in.final_acc{putf(&mut b,x);}
    putd(&mut b,p.trace_root);putd(&mut b,p.quotient_root);put32(&mut b,p.intermediate_roots.len()as u32);for d in &p.intermediate_roots{putd(&mut b,*d);}
    put32(&mut b,p.terminal.len()as u32);for x in &p.terminal{putf(&mut b,x.a);putf(&mut b,x.b);}
    put32(&mut b,p.queries.len()as u32);
    for q in &p.queries{put32(&mut b,q.idx);for x in q.cur.row{putf(&mut b,x);}put32(&mut b,q.cur.path.len()as u32);for d in &q.cur.path{putd(&mut b,*d);}for x in q.nxt.row{putf(&mut b,x);}put32(&mut b,q.nxt.path.len()as u32);for d in &q.nxt.path{putd(&mut b,*d);}put32(&mut b,q.layers.len()as u32);for l in &q.layers{putf(&mut b,l.lo.a);putf(&mut b,l.lo.b);putf(&mut b,l.hi.a);putf(&mut b,l.hi.b);put32(&mut b,l.plo.len()as u32);for d in &l.plo{putd(&mut b,*d);}put32(&mut b,l.phi.len()as u32);for d in &l.phi{putd(&mut b,*d);}}}
    b
}
struct Reader<'a>{b:&'a[u8],p:usize,ok:bool}
impl<'a> Reader<'a>{
    fn new(b:&'a[u8])->Self{Self{b,p:0,ok:true}}
    fn take(&mut self,n:usize)->&'a[u8]{if self.p+n>self.b.len(){self.ok=false;return &[];}let s=&self.b[self.p..self.p+n];self.p+=n;s}
    fn u32(&mut self)->u32{let s=self.take(4);if s.len()!=4{return 0;}u32::from_le_bytes(s.try_into().unwrap())}
    fn u64(&mut self)->u64{let s=self.take(8);if s.len()!=8{return 0;}u64::from_le_bytes(s.try_into().unwrap())}
    fn field(&mut self)->F{match F::canonical(self.u64()){Some(x)=>x,None=>{self.ok=false;F::default()}}}
    fn digest(&mut self)->Digest{let mut d=[F::default();4];for x in d.iter_mut(){*x=self.field();}d}
    fn path(&mut self,expected:u32)->Vec<Digest>{let n=self.u32();if n!=expected{self.ok=false;}let mut p=Vec::new();for _ in 0..n{p.push(self.digest());}p}
}
fn decode(bytes:&[u8])->Option<Proof>{
    let mut r=Reader::new(bytes);if r.take(8)!=b"QMG64P01"{r.ok=false;}if r.u32()!=1{r.ok=false;}let log_n=r.u32();if !(4..=24).contains(&log_n){r.ok=false;}
    let mut initial=[F::default();16];let mut final_acc=[F::default();16];for x in initial.iter_mut(){*x=r.field();}for x in final_acc.iter_mut(){*x=r.field();}
    let trace_root=r.digest();let quotient_root=r.digest();let nr=r.u32();if nr>32{r.ok=false;}let mut roots=Vec::new();for _ in 0..nr{roots.push(r.digest());}
    let nt=r.u32();if nt!=TERMINAL_SIZE as u32{r.ok=false;}let mut terminal=Vec::new();for _ in 0..nt{terminal.push(E::new(r.field(),r.field()));}
    let nq=r.u32();if nq!=QUERY_COUNT as u32{r.ok=false;}let log_s=log_n+3;let expected_layers=log_s-4;if nr+1!=expected_layers{r.ok=false;}
    let mut queries=Vec::new();
    for _ in 0..nq{let idx=r.u32();if idx>=(1u32<<log_s){r.ok=false;}let mut cur=TraceOpen::default();for x in cur.row.iter_mut(){*x=r.field();}cur.path=r.path(log_s);let mut nxt=TraceOpen::default();for x in nxt.row.iter_mut(){*x=r.field();}nxt.path=r.path(log_s);let nl=r.u32();if nl!=expected_layers{r.ok=false;}let mut layers=Vec::new();for l in 0..nl{let mut fp=FriPair::default();fp.lo=E::new(r.field(),r.field());fp.hi=E::new(r.field(),r.field());fp.plo=r.path(log_s-l);fp.phi=r.path(log_s-l);layers.push(fp);}queries.push(Query{idx,cur,nxt,layers});}
    if r.p!=bytes.len(){r.ok=false;}if !r.ok{return None;}Some(Proof{log_n,pub_in:PublicInput{initial,final_acc},trace_root,quotient_root,intermediate_roots:roots,terminal,queries})
}

struct ProverData{proof:Proof}

fn statement_for(log_n:u32,seed:u64)->PublicInput{
    let mut initial=[F::default();16];
    for i in 0..16{initial[i]=F::new(seed+17*i as u64+1);}
    let t=make_trace(1usize<<log_n,&initial);
    let mut final_acc=[F::default();16];
    for i in 0..16{final_acc[i]=t.last().unwrap()[16+i];}
    PublicInput{initial,final_acc}
}

fn prove(log_n:u32,seed:u64)->ProverData{
    let n=1usize<<log_n;
    let s=n*BLOWUP;
    let pub_in=statement_for(log_n,seed);
    let trace=make_trace(n,&pub_in.initial);

    let mut cols=vec![vec![F::default();n];AIR_WIDTH];
    for i in 0..n{for j in 0..AIR_WIDTH{cols[j][i]=trace[i][j];}}
    let shift=F::new(GENERATOR);
    let col_lde:Vec<Vec<F>>=cols.iter().map(|c|lde(c,BLOWUP,shift)).collect();
    let mut rows=vec![vec![F::default();AIR_WIDTH];s];
    for i in 0..s{for j in 0..AIR_WIDTH{rows[i][j]=col_lde[j][i];}}

    let trace_tree=Merkle::build(&rows);
    let mut tr=Transcript::new();
    tr.absorb_digest(Domain::Hash,public_digest(log_n,&pub_in));
    tr.absorb_digest(Domain::Leaf,trace_tree.root());
    let alpha=tr.challenge_ext();

    let omega_s=root_of_unity(log_n+3);
    let omega_n=root_of_unity(log_n);
    let last=omega_n.inv();
    let mut z=shift;
    let mut q=vec![E::default();s];
    for i in 0..s{
        let mut c=[F::default();AIR_WIDTH];
        let mut nx=[F::default();AIR_WIDTH];
        for j in 0..AIR_WIDTH{
            c[j]=rows[i][j];
            nx[j]=rows[(i+BLOWUP)%s][j];
        }
        q[i]=composition_at(z,&c,&nx,&pub_in,alpha,n,last);
        z*=omega_s;
    }

    let mut fri_layers=vec![q];
    let mut fri_trees=vec![Merkle::build(&e_leaves(&fri_layers[0]))];
    let quotient_root=fri_trees[0].root();
    let mut intermediate_roots=Vec::new();
    let mut offset=shift;

    let terminal=loop{
        let m=fri_layers.last().unwrap().len();
        if m<=TERMINAL_SIZE{
            break fri_layers.last().unwrap().clone();
        }
        let half=m/2;
        tr.absorb_digest(Domain::Fri,fri_trees.last().unwrap().root());
        let beta=tr.challenge_ext();
        let omega=root_of_unity(m.trailing_zeros());
        let mut x=offset;
        let inv2=F::new(2).inv();
        let mut next=vec![E::default();half];
        for i in 0..half{
            let a=fri_layers.last().unwrap()[i];
            let b=fri_layers.last().unwrap()[i+half];
            next[i]=(a+b)*inv2+beta*((a-b)*(inv2*x.inv()));
            x*=omega;
        }
        offset*=offset;
        if next.len()>TERMINAL_SIZE{
            fri_layers.push(next);
            fri_trees.push(Merkle::build(&e_leaves(fri_layers.last().unwrap())));
            intermediate_roots.push(fri_trees.last().unwrap().root());
        }else{
            break next;
        }
    };

    let mut te=Vec::new();
    for x in &terminal{te.push(x.a);te.push(x.b);}
    tr.absorb_digest(Domain::Fri,hash_fields(&te,Domain::Fri));

    let mut queries=vec![Query::default();QUERY_COUNT];
    for qp in queries.iter_mut(){
        qp.idx=tr.challenge_index(s as u32);
        let qidx=qp.idx as usize;
        let qnext=(qidx+BLOWUP)%s;
        for j in 0..AIR_WIDTH{
            qp.cur.row[j]=rows[qidx][j];
            qp.nxt.row[j]=rows[qnext][j];
        }
        qp.cur.path=trace_tree.path(qidx);
        qp.nxt.path=trace_tree.path(qnext);
        qp.layers=vec![FriPair::default();fri_layers.len()];
        let mut idx=qidx;
        for l in 0..fri_layers.len(){
            let m=fri_layers[l].len();
            let half=m/2;
            let base=idx%half;
            qp.layers[l].lo=fri_layers[l][base];
            qp.layers[l].hi=fri_layers[l][base+half];
            qp.layers[l].plo=fri_trees[l].path(base);
            qp.layers[l].phi=fri_trees[l].path(base+half);
            idx=base;
        }
    }

    let proof=Proof{
        log_n,
        pub_in,
        trace_root:trace_tree.root(),
        quotient_root,
        intermediate_roots,
        terminal,
        queries,
    };
    ProverData{proof}
}
fn terminal_degree_ok(terminal:&[E],offset:F,bound:usize)->bool{let c=interpolate_coset(terminal,offset);for x in &c[bound..]{if *x!=E::default(){return false;}}true}
fn verify(bytes:&[u8],expected_pub:&PublicInput)->bool{
    std::panic::catch_unwind(||{
        let p=match decode(bytes){Some(x)=>x,None=>return false};
        if p.pub_in!=*expected_pub{return false;}

        let n=1usize<<p.log_n;
        let s=n*BLOWUP;
        let mut tr=Transcript::new();
        tr.absorb_digest(Domain::Hash,public_digest(p.log_n,expected_pub));
        tr.absorb_digest(Domain::Leaf,p.trace_root);
        let alpha=tr.challenge_ext();

        let mut roots=vec![p.quotient_root];
        roots.extend_from_slice(&p.intermediate_roots);
        let mut betas=Vec::new();
        for root in &roots{
            tr.absorb_digest(Domain::Fri,*root);
            betas.push(tr.challenge_ext());
        }
        let mut te=Vec::new();
        for x in &p.terminal{te.push(x.a);te.push(x.b);}
        tr.absorb_digest(Domain::Fri,hash_fields(&te,Domain::Fri));

        let mut expected=vec![0u32;QUERY_COUNT];
        for x in expected.iter_mut(){*x=tr.challenge_index(s as u32);}

        let omega_s=root_of_unity(p.log_n+3);
        let omega_n=root_of_unity(p.log_n);
        let last=omega_n.inv();
        let mut final_offset=F::new(GENERATOR);
        for _ in 0..roots.len(){final_offset*=final_offset;}
        let mut final_bound=n;
        for _ in 0..roots.len(){final_bound=(final_bound+1)/2;}
        if final_bound>TERMINAL_SIZE
            || !terminal_degree_ok(&p.terminal,final_offset,final_bound)
        {
            return false;
        }

        for qi in 0..QUERY_COUNT{
            let q=&p.queries[qi];
            if q.idx!=expected[qi]{return false;}
            let qnext=(q.idx as usize+BLOWUP)%s;
            if !verify_path(q.idx,&q.cur.row,&q.cur.path,p.trace_root)
                || !verify_path(qnext as u32,&q.nxt.row,&q.nxt.path,p.trace_root)
            {
                return false;
            }
            if q.layers.len()!=roots.len(){return false;}

            let z=F::new(GENERATOR)*omega_s.pow(q.idx as u64);
            let mut expected_value=
                composition_at(z,&q.cur.row,&q.nxt.row,expected_pub,alpha,n,last);
            let mut idx=q.idx as usize;
            let mut offset=F::new(GENERATOR);

            for l in 0..roots.len(){
                let m=s>>l;
                let half=m/2;
                let base=idx%half;
                let fp=&q.layers[l];
                if !verify_path(base as u32,&[fp.lo.a,fp.lo.b],&fp.plo,roots[l])
                    || !verify_path((base+half)as u32,&[fp.hi.a,fp.hi.b],&fp.phi,roots[l])
                {
                    return false;
                }
                let selected=if idx<half{fp.lo}else{fp.hi};
                if selected!=expected_value{return false;}
                let x=offset*root_of_unity(m.trailing_zeros()).pow(base as u64);
                let inv2=F::new(2).inv();
                expected_value=(fp.lo+fp.hi)*inv2
                    +betas[l]*((fp.lo-fp.hi)*(inv2*x.inv()));
                idx=base;
                offset*=offset;
            }
            if p.terminal[idx]!=expected_value{return false;}
        }
        true
    }).unwrap_or(false)
}


#[derive(Copy,Clone)]
struct ScaleSpec{
    scale_log2:u32,
    trace_log2:u32,
    lde_row_log2:u32,
    total_lde_elements:u64,
    lde_rows:u64,
    trace_rows:u64,
    fri_fold_rounds:u64,
    proof_bytes:u64,
    raw_lde_bytes:u64,
    core_lower_bound_bytes:u64,
}

fn expected_proof_bytes_for_lde_log(lde_row_log2:u32)->u64{
    assert!((7..=24).contains(&lde_row_log2));
    let layers=(lde_row_log2-4)as u64;
    let intermediate_roots=layers-1;
    let fixed=
        8+4+4+
        32*8+
        (2*DIGEST_LEN*8)as u64+
        4+intermediate_roots*(DIGEST_LEN*8)as u64+
        4+(TERMINAL_SIZE*2*8)as u64+
        4;
    let mut layer_bytes=0u64;
    for layer in 0..layers{
        layer_bytes+=40+64*(lde_row_log2 as u64-layer);
    }
    let per_query=1040+64*lde_row_log2 as u64+layer_bytes;
    fixed+QUERY_COUNT as u64*per_query
}

fn scale_spec(scale_log2:u32)->Result<ScaleSpec,&'static str>{
    if !(20..=27).contains(&scale_log2){
        return Err("Scale log2 must be in 20..27");
    }
    let total=1u64<<scale_log2;
    let lde_rows=total/AIR_WIDTH as u64;
    let trace_rows=lde_rows/BLOWUP as u64;
    let lde_row_log2=scale_log2-6;
    let trace_log2=scale_log2-9;
    Ok(ScaleSpec{
        scale_log2,
        trace_log2,
        lde_row_log2,
        total_lde_elements:total,
        lde_rows,
        trace_rows,
        fri_fold_rounds:(lde_row_log2-4)as u64,
        proof_bytes:expected_proof_bytes_for_lde_log(lde_row_log2),
        raw_lde_bytes:total*8,
        core_lower_bound_bytes:(73*total)/4,
    })
}

fn scale_csv_header(){
    println!(
        "implementation,scale_log2,total_lde_elements,lde_rows,trace_rows,\
fri_fold_rounds,proof_bytes,proof_fnv,core_lower_bound_bytes,prove_seconds,\
verify_seconds,prove_lde_elements_per_second,verify_proof_bytes_per_second,\
valid,wrong_statement_rejected,mutation_rejected,trailing_rejected"
    );
}

fn scale_contract_table(){
    println!(
        "scale_log2,total_lde_elements,committed_columns,lde_rows,\
lde_row_log2,trace_rows,trace_log2,trace_total_elements,blowup,\
trace_merkle_leaves,trace_merkle_height,fri_initial_fp2_elements,\
fri_fold_rounds,cpu_fri_committed_roots,fri_vectors_including_terminal,\
gpu_fri_root_count,fri_terminal_elements,query_count,proof_bytes,\
raw_trace_bytes,raw_lde_bytes,quotient_fp2_bytes,\
core_lower_bound_bytes,gpu_leaf_count,gpu_final_rows"
    );
    for k in 20..=27{
        let s=scale_spec(k).expect("contract Scale");
        let trace_total_elements=s.trace_rows*AIR_WIDTH as u64;
        let fri_vectors=s.fri_fold_rounds+1;
        let values=[
            s.scale_log2.to_string(),
            s.total_lde_elements.to_string(),
            AIR_WIDTH.to_string(),
            s.lde_rows.to_string(),
            s.lde_row_log2.to_string(),
            s.trace_rows.to_string(),
            s.trace_log2.to_string(),
            trace_total_elements.to_string(),
            BLOWUP.to_string(),
            s.lde_rows.to_string(),
            s.lde_row_log2.to_string(),
            s.lde_rows.to_string(),
            s.fri_fold_rounds.to_string(),
            s.fri_fold_rounds.to_string(),
            fri_vectors.to_string(),
            fri_vectors.to_string(),
            TERMINAL_SIZE.to_string(),
            QUERY_COUNT.to_string(),
            s.proof_bytes.to_string(),
            s.total_lde_elements.to_string(),
            s.raw_lde_bytes.to_string(),
            (s.total_lde_elements/4).to_string(),
            s.core_lower_bound_bytes.to_string(),
            s.lde_rows.to_string(),
            TERMINAL_SIZE.to_string(),
        ];
        println!("{}",values.join(","));
    }
}

fn scale_contract_test(){
    assert_eq!(expected_proof_bytes_for_lde_log(7),177_308);
    let mut previous_proof_bytes=0u64;
    for k in 20..=27{
        let s=scale_spec(k).expect("contract Scale");
        assert_eq!(s.total_lde_elements,1u64<<k);
        assert_eq!(s.lde_rows*AIR_WIDTH as u64,s.total_lde_elements);
        assert_eq!(s.trace_rows*BLOWUP as u64,s.lde_rows);
        assert_eq!(s.trace_log2,k-9);
        assert_eq!(s.lde_row_log2,k-6);
        assert_eq!(s.fri_fold_rounds,(k-10)as u64);
        assert_eq!(s.raw_lde_bytes,8*s.total_lde_elements);
        assert_eq!(s.core_lower_bound_bytes,(73*s.total_lde_elements)/4);
        assert_eq!(s.trace_rows*AIR_WIDTH as u64,s.total_lde_elements/BLOWUP as u64);
        assert_eq!(s.lde_rows,s.total_lde_elements/AIR_WIDTH as u64);
        assert_eq!(s.lde_row_log2,s.lde_rows.trailing_zeros());
        assert_eq!(s.fri_fold_rounds+1,(s.lde_row_log2-3)as u64);
        assert_eq!(TERMINAL_SIZE,16);
        assert_eq!(QUERY_COUNT,64);
        assert!(s.proof_bytes>previous_proof_bytes);
        assert_eq!(root_of_unity(s.trace_log2).pow(s.trace_rows),F::new(1));
        assert_eq!(root_of_unity(s.lde_row_log2).pow(s.lde_rows),F::new(1));
        previous_proof_bytes=s.proof_bytes;
    }
    assert!(scale_spec(19).is_err());
    assert!(scale_spec(28).is_err());
    println!("rust scale contract: PASS");
}

fn scale_run(scale_log2:u32,print_header:bool){
    let spec=scale_spec(scale_log2).expect("Scale log2 must be in 20..27");

    let prove_begin=Instant::now();
    let proof={
        let prover_data=prove(spec.trace_log2,7);
        prover_data.proof
    };
    let bytes=encode(&proof);
    let prove_seconds=prove_begin.elapsed().as_secs_f64();
    assert_eq!(bytes.len()as u64,spec.proof_bytes);

    let expected=statement_for(spec.trace_log2,7);
    let verify_begin=Instant::now();
    let valid=verify(&bytes,&expected);
    let verify_seconds=verify_begin.elapsed().as_secs_f64();

    let mut wrong=expected.clone();
    wrong.initial[0]+=F::new(1);
    let wrong_statement_rejected=!verify(&bytes,&wrong);

    let mut mutated=bytes.clone();
    let middle=mutated.len()/2;
    mutated[middle]^=1;
    let mutation_rejected=!verify(&mutated,&expected);

    let mut trailing=bytes.clone();
    trailing.push(0);
    let trailing_rejected=!verify(&trailing,&expected);

    assert!(valid);
    assert!(wrong_statement_rejected);
    assert!(mutation_rejected);
    assert!(trailing_rejected);

    if print_header{scale_csv_header();}
    println!(
        "rust,{},{},{},{},{},{},{},{},{:.12},{:.12},{:.12},{:.12},{},{},{},{}",
        spec.scale_log2,
        spec.total_lde_elements,
        spec.lde_rows,
        spec.trace_rows,
        spec.fri_fold_rounds,
        bytes.len(),
        hx(fnv1a(&bytes)),
        spec.core_lower_bound_bytes,
        prove_seconds,
        verify_seconds,
        spec.total_lde_elements as f64/prove_seconds,
        bytes.len()as f64/verify_seconds,
        if valid{1}else{0},
        if wrong_statement_rejected{1}else{0},
        if mutation_rejected{1}else{0},
        if trailing_rejected{1}else{0},
    );
}

fn scale_matrix(first:u32,last:u32){
    if first<20 || last>27 || first>last{
        eprintln!("scale-matrix range must be within 20..27");
        std::process::exit(2);
    }
    scale_csv_header();
    for k in first..=last{scale_run(k,false);}
}

fn fnv1a(b:&[u8])->u64{let mut h=1_469_598_103_934_665_603u64;for x in b{h^=*x as u64;h=h.wrapping_mul(1_099_511_628_211);}h}
fn hx(x:u64)->String{format!("{:016x}",x)}
fn self_test(){
    assert_eq!(F::new(P-1)+F::new(2),F::new(1));
    assert_eq!(F::new(1_234_567)*F::new(1_234_567).inv(),F::new(1));
    let e=E::new(F::new(11),F::new(9));
    assert_eq!(e*e.inv(),E::from_f(F::new(1)));

    let mut z=[F::default();WIDTH];
    permute(&mut z);
    assert_eq!(z[0].0,0x18bf_b581_dfb0_a9a9);
    assert_eq!(z[11].0,0x1de9_b4ff_a41e_4d89);
    let seq=(0..12).map(|i|F::new(i)).collect::<Vec<_>>();
    assert_eq!(hash_fields(&seq,Domain::Hash)[0].0,0x5f06_8621_cee9_6577);

    let expected=statement_for(4,3);
    let t=make_trace(16,&expected.initial);
    for i in 0..t.len()-1{assert!(valid_transition(&t[i],&t[i+1]));}
    let mut x=(0..16).map(|i|F::new((i*i+7)as u64)).collect::<Vec<_>>();
    let y=x.clone();ntt(&mut x,false);ntt(&mut x,true);assert_eq!(x,y);

    let pd=prove(4,3);
    let bytes=encode(&pd.proof);
    assert!(pd.proof.pub_in==expected);
    assert!(verify(&bytes,&expected));

    let mut wrong_statement=expected.clone();
    wrong_statement.initial[0]+=F::new(1);
    assert!(!verify(&bytes,&wrong_statement));
    wrong_statement=expected.clone();
    wrong_statement.final_acc[0]+=F::new(1);
    assert!(!verify(&bytes,&wrong_statement));

    let mut public_bad=bytes.clone();
    public_bad[16]^=1;
    assert!(!verify(&public_bad,&expected));

    let mut bad_proof=pd.proof.clone();
    bad_proof.trace_root[0]+=F::new(1);
    assert!(!verify(&encode(&bad_proof),&expected));

    bad_proof=pd.proof.clone();
    bad_proof.queries[0].cur.row[0]+=F::new(1);
    assert!(!verify(&encode(&bad_proof),&expected));

    bad_proof=pd.proof.clone();
    bad_proof.terminal[0].a+=F::new(1);
    assert!(!verify(&encode(&bad_proof),&expected));

    let mut bad=bytes.clone();
    let mid=bad.len()/2;bad[mid]^=1;
    assert!(!verify(&bad,&expected));

    let mut trailing=bytes;trailing.push(0);
    assert!(!verify(&trailing,&expected));
    println!("rust correctness: PASS");
}
fn vectors(){let mut z=[F::default();WIDTH];permute(&mut z);let seq=(0..12).map(|i|F::new(i)).collect::<Vec<_>>();let h=hash_fields(&seq,Domain::Hash);let pd=prove(4,3);let bytes=encode(&pd.proof);println!("poseidon_zero_0={}",hx(z[0].0));println!("poseidon_zero_11={}",hx(z[11].0));println!("hash_seq_0={}",hx(h[0].0));println!("proof_size={}",bytes.len());println!("proof_fnv={}",hx(fnv1a(&bytes)));}
fn bench(log_n:u32){
    assert!((4..=24).contains(&log_n));
    let mut sink=0u64;
    let muls=2_000_000usize;
    let mut x=F::new(3);let y=F::new(5);
    let a=Instant::now();
    for i in 0..muls{x=x*y+F::new(i as u64);sink^=x.0;}
    let sec=a.elapsed().as_secs_f64();
    println!("rust,field_mul_add,{},{},{}",muls,sec,muls as f64/sec);

    let mut s=[F::default();WIDTH];
    let perms=200usize;
    let a=Instant::now();
    for i in 0..perms{s[0]+=F::new(i as u64);permute(&mut s);sink^=s[0].0;}
    let sec=a.elapsed().as_secs_f64();
    println!("rust,poseidon2_permute,{},{},{}",perms,sec,perms as f64/sec);

    let a=Instant::now();
    let p=prove(log_n,7);
    let bytes=encode(&p.proof);
    let sec=a.elapsed().as_secs_f64();
    println!("rust,stark_prove,{},{},{}",1usize<<log_n,sec,(1usize<<log_n)as f64/sec);

    let expected=statement_for(log_n,7);
    let a=Instant::now();
    assert!(verify(&bytes,&expected));
    let sec=a.elapsed().as_secs_f64();
    println!("rust,stark_verify,{},{},{}",bytes.len(),sec,bytes.len()as f64/sec);
    if sink==0xdead_beef{eprintln!("");}
}

fn proof_file(scale_log2:u32,path:&str){
    let spec=scale_spec(scale_log2).unwrap_or_else(|e|panic!("{}",e));
    let pd=prove(spec.trace_log2,7);
    let bytes=encode(&pd.proof);
    let expected=statement_for(spec.trace_log2,7);
    assert_eq!(bytes.len()as u64,spec.proof_bytes);
    assert!(verify(&bytes,&expected));
    fs::write(path,&bytes).expect("cannot write proof file");
    let root=pd.proof.trace_root.iter().map(|x|format!("0x{}",hx(x.0))).collect::<Vec<_>>().join(";");
    println!("status=PASS\nimplementation=rust\nproof_format=QMG64P01\nscale_log2={}\ntrace_log2={}\nlde_rows={}\nfri_fold_rounds={}\nquery_count={}\nterminal_elements={}\nproof_bytes={}\nproof_fnv={}\ntrace_root={}\nproof_file={}\nverifier=PASS",
        scale_log2,spec.trace_log2,spec.lde_rows,spec.fri_fold_rounds,QUERY_COUNT,TERMINAL_SIZE,bytes.len(),hx(fnv1a(&bytes)),root,path);
}

fn verify_file(scale_log2:u32,path:&str){
    let spec=scale_spec(scale_log2).unwrap_or_else(|e|panic!("{}",e));
    let bytes=fs::read(path).expect("cannot read proof file");
    let expected=statement_for(spec.trace_log2,7);
    assert!(verify(&bytes,&expected));
    println!("status=PASS\nimplementation=rust_verifier\nscale_log2={}\nproof_bytes={}\nproof_fnv={}\nverifier=PASS",scale_log2,bytes.len(),hx(fnv1a(&bytes)));
}

fn main(){
    let args=env::args().collect::<Vec<_>>();
    let cmd=args.get(1).map(String::as_str).unwrap_or("test");
    match cmd{
        "test"=>self_test(),
        "vectors"=>vectors(),
        "scale-contract"=>scale_contract_test(),
        "scale-table"=>scale_contract_table(),
        "scale-run"=>scale_run(
            args.get(2).and_then(|x|x.parse().ok()).unwrap_or(20),
            true
        ),
        "scale-matrix"=>scale_matrix(
            args.get(2).and_then(|x|x.parse().ok()).unwrap_or(20),
            args.get(3).and_then(|x|x.parse().ok()).unwrap_or(27)
        ),
        "bench"=>bench(args.get(2).and_then(|x|x.parse().ok()).unwrap_or(7)),
        "proof-file"=>proof_file(args.get(2).and_then(|x|x.parse().ok()).unwrap_or(20),args.get(3).map(String::as_str).unwrap_or("rust-proof.qmg64p01")),
        "verify-file"=>verify_file(args.get(2).and_then(|x|x.parse().ok()).unwrap_or(20),args.get(3).map(String::as_str).unwrap_or("rust-proof.qmg64p01")),
        _=>panic!(
            "usage: test|vectors|scale-contract|scale-table|scale-run K|scale-matrix [K_MIN] [K_MAX]|bench [trace_log2]|proof-file K PATH|verify-file K PATH"
        ),
    }
}
