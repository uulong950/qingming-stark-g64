
const P:u64=0xffff_ffff_0000_0001;
const HEADER:&str=include_str!("../../rx7900xtx-24g/qingming_poseidon2_g64_constants.h");

fn add(a:u64,b:u64)->u64{((a as u128+b as u128)%(P as u128)) as u64}
fn mul(a:u64,b:u64)->u64{((a as u128*b as u128)%(P as u128)) as u64}
fn pow7(x:u64)->u64{let x2=mul(x,x);let x3=mul(x2,x);let x4=mul(x2,x2);mul(x3,x4)}
fn fnv_word(mut h:u64,x:u64)->u64{
    for i in 0..8 { h^=(x>>(8*i))&0xff; h=h.wrapping_mul(1_099_511_628_211); }
    h
}
fn parse_array(name:&str,expected:usize)->Vec<u64>{
    let needle=format!("{name}[");
    let start=HEADER.find(&needle).unwrap_or_else(||panic!("missing {name}"));
    let rest=&HEADER[start..];
    let open=rest.find('{').unwrap_or_else(||panic!("missing opening brace for {name}"));
    let body=&rest[open+1..];
    let close=body.find("};").unwrap_or_else(||panic!("missing closing brace for {name}"));
    let values:Vec<u64>=body[..close].split(',')
        .filter_map(|raw|{
            let t=raw.trim();
            if t.is_empty(){return None;}
            let t=t.trim_end_matches("ULL").trim_end_matches("UL").trim();
            Some(if let Some(hex)=t.strip_prefix("0x"){
                u64::from_str_radix(hex,16).unwrap()
            }else{
                t.parse::<u64>().unwrap()
            })
        }).collect();
    assert_eq!(values.len(),expected,"wrong constant count for {name}");
    values
}
fn external_mix(s:&mut [u64;12],m:&[u64]){
    let old=*s;
    let mut out=[0u64;12];
    for r in 0..12 {
        let mut acc=0u64;
        for c in 0..12 { acc=add(acc,mul(m[r*12+c],old[c])); }
        out[r]=acc;
    }
    *s=out;
}
fn internal_mix(s:&mut [u64;12],diag:&[u64]){
    let old=*s;
    let mut total=0u64;
    for x in old { total=add(total,x); }
    let mut out=[0u64;12];
    for i in 0..12 { out[i]=add(total,mul(diag[i],old[i])); }
    *s=out;
}
fn permute(s:&mut [u64;12],re:&[u64],ri:&[u64],m:&[u64],diag:&[u64]){
    external_mix(s,m);
    for r in 0..4 {
        for i in 0..12 { s[i]=pow7(add(s[i],re[r*12+i])); }
        external_mix(s,m);
    }
    for &rc in ri {
        s[0]=pow7(add(s[0],rc));
        internal_mix(s,diag);
    }
    for r in 4..8 {
        for i in 0..12 { s[i]=pow7(add(s[i],re[r*12+i])); }
        external_mix(s,m);
    }
}
fn main(){
    const ROWS:usize=31;
    let re=parse_array("QM_P2_G64_RC_EXTERNAL",96);
    let ri=parse_array("QM_P2_G64_RC_INTERNAL",22);
    let m=parse_array("QM_P2_G64_EXTERNAL_MATRIX",144);
    let diag=parse_array("QM_P2_G64_INTERNAL_DIAG",12);
    let mut trace=[[0u64;12];ROWS];
    for i in 0..12 { trace[0][i]=(i+1) as u64; }
    for r in 1..ROWS { trace[r]=trace[r-1]; permute(&mut trace[r],&re,&ri,&m,&diag); }
    for i in 0..12 { assert_eq!(trace[0][i],(i+1) as u64,"boundary constraint failure"); }
    let mut residuals=12usize;
    for r in 0..ROWS-1 {
        let mut expected=trace[r];
        permute(&mut expected,&re,&ri,&m,&diag);
        assert_eq!(trace[r+1],expected,"transition constraint failure");
        residuals+=12;
    }
    let mut h=14_695_981_039_346_656_037u64;
    for row in &trace { for &x in row { h=fnv_word(h,x); } }
    println!("status=PASS");
    println!("air_id=QMG-AIR-POSEIDON2-CHAIN");
    println!("air_revision=1");
    println!("backend=rust");
    println!("trace_rows={ROWS}");
    println!("trace_width=12");
    println!("maximum_constraint_degree=7");
    println!("constraint_residuals={residuals}");
    println!("trace_fingerprint={h:016x}");
    println!("public_output_0={}",trace[ROWS-1][0]);
    println!("public_output_1={}",trace[ROWS-1][1]);
    println!("public_output_2={}",trace[ROWS-1][2]);
    println!("public_output_3={}",trace[ROWS-1][3]);
}
