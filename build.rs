extern crate bindgen;
extern crate cc;

use std::env;
use std::path::PathBuf;

fn main() {
    // Compile cpp files into static library
    cc::Build::new()
        .file("neoscrypt/neoscrypt.c")
        .compile("neoscrypt");

    println!("cargo:rustc-link-lib=neoscrypt"); // the name of the library

    let bindings = bindgen::Builder::default()
        .header("neoscrypt/neoscrypt.h")
        .trust_clang_mangling(false)
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
