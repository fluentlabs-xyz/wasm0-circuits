use std::env;
use std::io::{BufReader, Write};
use golang_utils;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Link
    let lib_name = "gas_injector";
    let go_mod_file_rel_path = manifest_dir + "/../geth-utils/";
    let go_package_name = "zkwasm-gas-injector";
    let go_mod_file_name = "go.mod";
    let go_package_path = golang_utils::go_package_system_path(go_package_name, go_mod_file_name, go_mod_file_rel_path.as_str()).unwrap();
    // TODO detect local arch and choose dirs accordingly
    let mut local_libs_subdirs = vec![];
    let arch = env::consts::ARCH;
    match env::consts::OS {
        "linux" => {
            if arch.contains("x86_64") || arch.contains("amd64") {
                local_libs_subdirs.push("linux-amd64");
            } else {
                panic!("unsupported arch '{}'", arch)
            }
        },
        "macos" => {
            if arch.contains("aarch64") { local_libs_subdirs.push("darwin-aarch64"); }
            else if arch.contains("x86_64") || arch.contains("amd64") {
                local_libs_subdirs.push("darwin-amd64");
            } else {
                panic!("unsupported arch '{}'", arch)
            }
        },
        platform => panic!("unsupported build platform '{}'", platform)
    }
    if cfg!(windows) {

    } else if cfg!(unix) {

    } else {
        panic!("failed to detect build platform")
    }
    for subdir in local_libs_subdirs {
        let local_libs_path = go_package_path.clone() + "/packaged/lib/" + subdir;
        println!("cargo:rustc-link-search={}", &local_libs_path);
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", &local_libs_path);
    }
    println!("cargo:rustc-link-lib={}", lib_name);
}
