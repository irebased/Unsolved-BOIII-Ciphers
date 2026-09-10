mod actual {
    include!("source/ra-oracle/src/ioc.rs");
    pub fn letters(b: &[u8]) -> usize { letter_count(b) }
    pub fn minimum() -> usize { MIN_SCORED_LETTERS }
    pub fn threshold() -> f64 { IOC_ENGLISH_THRESHOLD }
}
fn fixtures() -> Vec<(&'static str, Vec<u8>)> {
    let mut concentrated=vec![b'A';90];concentrated.resize(546,0);
    let prose=b"The mountain must be searched for the frozen one. In the cell below the waves is where honor suffers. When finished we will return to the house and the infinite. A city of fire surrounds the warrior, the last of his kind.";
    let mut embedded=prose.to_vec();embedded.resize(546,0x80);
    let mut state=0x6a09e667f3bcc909u64;let mut random=Vec::new();
    for _ in 0..546 {let mut x=state;x^=x<<13;x^=x>>7;x^=x<<17;state=x;random.push((x.wrapping_mul(0x2545_f491_4f6c_dd1d)&255) as u8);}
    vec![("ninety_A_plus_nonletters",concentrated),("known_prose_plus_nonletters",embedded),("fixed_seed_uniform_bytes",random)]
}
fn main(){
 println!("constants\t{}\t{:.17}",actual::minimum(),actual::threshold());
 for(name,b) in fixtures(){let n=actual::letters(&b);let v=actual::index_of_coincidence(&b);let pass=n>=actual::minimum()&&v+1e-12>=actual::threshold();println!("fixture\t{}\t{}\t{}\t{:.17}\t{}",name,b.len(),n,v,pass);}
}
