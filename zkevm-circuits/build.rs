use std::{
    env,
};

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let external_libs = vec![
        ("zkwasm-gas-injector", "gas_injector"),
        ("zkwasm-wasmi", "wasmi_c_api"),
    ];

    let mut local_libs_paths: Vec<String> = vec![];
    let mut local_libs_names: Vec<String> = vec![];
    let arch = env::consts::ARCH;
    let go_mod_file_rel_path = manifest_dir + "/../geth-utils";
    for (go_package_name, go_lib_name) in external_libs {
        local_libs_names.push(go_lib_name.to_string());
        let mut local_libs_subdirs = vec![];
        let go_mod_file_name = "go.mod";
        let go_package_path = golang_utils::go_package_system_path(
            go_package_name,
            go_mod_file_name,
            go_mod_file_rel_path.as_str()
        ).unwrap();
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
        for subdir in local_libs_subdirs {
            let local_libs_path = go_package_path.clone() + "/packaged/lib/" + subdir;
            local_libs_paths.push(local_libs_path);
        }
    }
    for (i, local_lib_path) in local_libs_paths.iter().enumerate() {
        println!("cargo:rustc-link-lib={}", local_libs_names[i]);
        println!("cargo:rustc-link-search={}", local_lib_path);
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", local_lib_path);

    }
}
