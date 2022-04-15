#[cfg(windows)]
use std::path::PathBuf;

#[cfg(all(not(windows), not(feature = "static")))]
use std::process::Command;

#[cfg(all(not(windows), feature = "static"))]
use cmake;

#[cfg(all(windows, not(feature = "npcap"), not(feature = "static")))]
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut lib_path = PathBuf::from(&dir).join("winpcap");
    if cfg!(target_arch = "x86_64") {
        lib_path.push("x64");
    }
    println!("cargo:rustc-link-search=native={}", lib_path.display());
    println!("cargo:rustc-link-lib=packet");
    println!("cargo:rustc-link-lib=wpcap");
}

#[cfg(all(windows, feature = "npcap", not(feature = "static")))]
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut lib_path = PathBuf::from(&dir).join("npcap");
    if cfg!(target_arch = "x86_64") {
        lib_path.push("x64");
    } else if cfg!(target_arch = "aarch64") {
        lib_path.push("ARM64");
    }
    println!("cargo:rustc-link-search=native={}", lib_path.display());
    println!("cargo:rustc-link-lib=packet");
    println!("cargo:rustc-link-lib=wpcap");
}

#[cfg(all(not(windows), not(feature = "static")))]
fn main() {
    if pkg_config::probe_library("libpcap").is_ok() {
        return;
    }

    if let Ok(output) = Command::new("pcap-config").arg("--libs").output() {
        parse_libs_cflags(&output.stdout);
    }

    println!("cargo:rustc-link-search=native=/usr/lib");
}

#[cfg(all(not(windows), not(feature = "static")))]
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

#[cfg(all(not(windows), not(feature = "static")))]
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

#[cfg(all(not(windows), feature = "static"))]
fn main() {
    #[cfg(debug_assertions)]
    const PROFILE: &'static str = "Debug";
    #[cfg(not(debug_assertions))]
    const PROFILE: &'static str = "Release";

    let dst = cmake::Config::new("libpcap")
        .profile(PROFILE)
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("ENABLE_REMOTE", "ON")
        .build_target("pcap_static")
        .build();
    println!("cargo:rustc-link-search=native={}", dst.display());
    println!("cargo:rustc-link-lib=static=pcap");
}
