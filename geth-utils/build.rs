use std::{
    env,
    io::{self, Write},
};

fn main() {
    let lib_name = "geth-utils";
    let out_dir = env::var("OUT_DIR").unwrap();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Build
    if let Err(e) = gobuild::Build::new()
        .file("./lib/lib.go")
        .try_compile(lib_name)
    {
        // The error type is private so have to check the error string
        if format!("{}", e).starts_with("Failed to find tool.") {
            fail(
                " Failed to find Go. Please install Go 1.16 or later \
                following the instructions at https://golang.org/doc/install.
                On linux it is also likely available as a package."
                    .to_string(),
            );
        } else {
            fail(format!("{}", e));
        }
    }

    // Files the lib depends on that should recompile the lib
    let dep_files = vec![
        "./gethutil/asm.go",
        "./gethutil/trace.go",
        "./gethutil/util.go",
        "./go.mod",
    ];
    for file in dep_files {
        println!("cargo:rerun-if-changed={}", file);
    }

    // Link
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static={}", lib_name);
    let lib_name = "gas_injector";
    let go_package_name = "zkwasm-gas-injector";
    let go_mod_file_rel_path = manifest_dir.as_str();
    let go_mod_file_name = "go.mod";
    let go_package_path = golang_utils::go_package_system_path(go_package_name, go_mod_file_name, go_mod_file_rel_path).unwrap();
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
    for subdir in local_libs_subdirs {
        let local_libs_path = go_package_path.clone() + "/packaged/lib/" + subdir;
        println!("cargo:rustc-link-search={}", &local_libs_path);
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", &local_libs_path);
    }
    println!("cargo:rustc-link-lib={}", lib_name);
}

fn fail(message: String) {
    let _ = writeln!(
        io::stderr(),
        "\n\nError while building geth-utils: {}\n\n",
        message
    );
    std::process::exit(1);
}
