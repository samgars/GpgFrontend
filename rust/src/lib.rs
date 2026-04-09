#[unsafe(no_mangle)]
pub extern "C" fn gf_rust_hello() {
    println!(
        "Hello from Rust! (Rust Support Library version {})",
        env!("CARGO_PKG_VERSION")
    );
}
