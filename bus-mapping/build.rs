use std::env;
use std::io::{self, Write};

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Link
    // println!("cargo:rustc-link-search=native={}", out_dir);
    // println!("cargo:rustc-link-lib=static={}", lib_name);
    let local_libs_subdirs = vec!["linux-amd64", "darwin-amd64", "darwin-aarch64"];
    for subdir in local_libs_subdirs {
        let local_libs_path = manifest_dir.clone() + "/../packaged/lib/" + subdir;
        println!("cargo:rustc-link-search={}", &local_libs_path);
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", &local_libs_path);
    }
    println!("cargo:rustc-link-lib=gas_injector");
    // println!("cargo:rustc-flags={}", "-l gas_injector -L /usr/local/lib");
}
