
const P:u64=0xffff_ffff_0000_0001;
fn add(a:u64,b:u64)->u64{((a as u128+b as u128)%(P as u128)) as u64}
fn fnv_word(mut h:u64,x:u64)->u64{
    for i in 0..8 { h^=((x>>(8*i))&0xff) as u64; h=h.wrapping_mul(1_099_511_628_211); }
    h
}
fn main(){
    const ROWS:usize=32;
    let mut trace=[[0u64;2];ROWS];
    trace[0]=[1,1];
    for r in 1..ROWS {
        trace[r][0]=trace[r-1][1];
        trace[r][1]=add(trace[r-1][0],trace[r-1][1]);
    }
    assert_eq!(trace[0],[1,1],"boundary constraint failure");
    let mut residuals=2usize;
    for r in 0..ROWS-1 {
        assert_eq!(trace[r+1][0],trace[r][1],"transition constraint 0 failure");
        assert_eq!(trace[r+1][1],add(trace[r][0],trace[r][1]),"transition constraint 1 failure");
        residuals+=2;
    }
    let mut h=14_695_981_039_346_656_037u64;
    for row in &trace { for &x in row { h=fnv_word(h,x); } }
    println!("status=PASS");
    println!("air_id=QMG-AIR-FIBONACCI");
    println!("air_revision=1");
    println!("backend=rust");
    println!("trace_rows={ROWS}");
    println!("trace_width=2");
    println!("maximum_constraint_degree=1");
    println!("constraint_residuals={residuals}");
    println!("trace_fingerprint={h:016x}");
    println!("public_output_0={}",trace[ROWS-1][0]);
    println!("public_output_1={}",trace[ROWS-1][1]);
}
