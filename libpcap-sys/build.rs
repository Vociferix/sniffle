#[cfg(windows)]
use std::path::PathBuf;

#[cfg(not(windows))]
use std::process::Command;

#[cfg(windows)]
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut lib_path = PathBuf::from(&dir).join("winlib");
    if cfg!(target_arch = "x86_64") {
        lib_path.push("x64");
    }
    println!("cargo:rustc-link-search=native={}", lib_path.display());
    println!("cargo:rustc-link-lib=packet");
    println!("cargo:rustc-link-lib=wpcap");
}

#[cfg(not(windows))]
fn main() {
    if pkg_config::probe_library("libpcap").is_ok() {
        return;
    }

    match Command::new("pcap-config").arg("--libs").output() {
        Ok(output) => parse_libs_cflags(&output.stdout),
        Err(_) => (),
    }

    println!("cargo:rustc-link-search=native=/usr/lib");
}

#[cfg(not(windows))]
fn parse_libs_cflags(output: &[u8]) {
    let words = split_flags(output);
    let parts = words
        .iter()
        .filter(|l| l.len() > 2)
        .map(|arg| (&arg[0..2], &arg[2..]))
        .collect::<Vec<_>>();

    for &(flag, val) in &parts {
        match flag {
            "-L" => {
                println!("cargo:rustc-link-search=native={}", val);
            }
            "-F" => {
                println!("cargo:rustc-link-search=framework={}", val);
            }
            "-l" => {
                println!("cargo:rustc-link-lib={}", val);
            }
            _ => {}
        }
    }
}

#[cfg(not(windows))]
fn split_flags(output: &[u8]) -> Vec<String> {
    let mut word = Vec::new();
    let mut words = Vec::new();
    let mut escaped = false;

    for &b in output {
        match b {
            _ if escaped => {
                escaped = false;
                word.push(b);
            }
            b'\\' => escaped = true,
            b'\t' | b'\n' | b'\r' | b' ' => {
                if !word.is_empty() {
                    words.push(String::from_utf8(word).unwrap());
                    word = Vec::new();
                }
            }
            _ => word.push(b),
        }
    }

    if !word.is_empty() {
        words.push(String::from_utf8(word).unwrap());
    }

    words
}
