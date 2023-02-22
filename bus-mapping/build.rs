use std::env;
use std::io::{BufReader, Write};
use golang_utils;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Link
    let go_mod_file_rel_path = manifest_dir + "/../geth-utils/";
    let go_package_name = "zkwasm-gas-injector";
    let go_mod_file_name = "go.mod";
    let go_package_path = golang_utils::go_package_system_path(go_package_name, go_mod_file_name, go_mod_file_rel_path.as_str()).unwrap();
    let local_libs_subdirs = vec!["darwin-amd64", "darwin-aarch64", "linux-amd64"];
    for subdir in local_libs_subdirs {
        let local_libs_path = go_package_path.clone() + "/packaged/lib/" + subdir;
        println!("cargo:rustc-link-search={}", &local_libs_path);
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", &local_libs_path);
    }
    println!("cargo:rustc-link-lib=gas_injector");
}
