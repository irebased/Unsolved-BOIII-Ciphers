// Identity: ASTRA. Exact Rust ASCII-whitespace mechanics, no target input.
fn main() {
    let ws: Vec<u8> = (0..=255u8).filter(|x| x.is_ascii_whitespace()).collect();
    assert_eq!(ws, vec![9, 10, 12, 13, 32]);
    let text = "A\u{000b}B C";
    let out = text.split_ascii_whitespace().rev().collect::<Vec<_>>().join(" ");
    assert_eq!(out, "C A\u{000b}B");
    println!("[{:?}, {:?}]", ws, out.as_bytes());
}
