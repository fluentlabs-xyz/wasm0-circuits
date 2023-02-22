use std::{env};
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn go_package_system_path(golang_package_name: &str, golang_mod_file_name: &str, golang_mod_file_rel_path: &str) -> Result<String, String> {
    let golang_path = env::var("GOPATH").unwrap();
    let golang_pkg_mod_path = golang_path + "/pkg/mod";

    let file = File::open(golang_mod_file_rel_path.to_string() + "/" + golang_mod_file_name).unwrap();
    let reader = BufReader::new(file);
    for line in reader.lines().map(|line| line.unwrap()) {
        if line.contains(golang_package_name) {
            let line_trimmed = line.trim();
            // TODO fetch package full name and version
            let line_splitted: Vec<&str> = line_trimmed.split(" ").collect();
            let package_full_name = line_splitted[0];
            let package_version = line_splitted[1];
            // TODO form path to package (need golang home)
            let golang_package_path = format!("{}/{}@{}", golang_pkg_mod_path, package_full_name, package_version);
            return Ok(golang_package_path);
        }
    }
    Err(String::from("golang mod file doesnt contain package name"))
}
