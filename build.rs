use std::env;

fn main() {
    if env::var("DEP_OPENSSL_VERSION").unwrap() == "111" {
        println!("cargo:rustc-cfg=ossl111");
    }
}
