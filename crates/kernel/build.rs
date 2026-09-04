use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bpf");

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set by cargo");

    // TARGET (not std::env::consts::ARCH, which reflects the host running
    // this build script, not necessarily what we're building for under
    // cross-compilation) is the triple cargo sets for build scripts.
    let target = std::env::var("TARGET").expect("TARGET not set by cargo");
    let target_arch = target.split('-').next().expect("malformed TARGET triple");

    let bpf_arch_define = match target_arch {
        "x86_64" => "__TARGET_ARCH_x86",
        "aarch64" => "__TARGET_ARCH_arm64",
        other => panic!(
            "unsupported target architecture for eBPF build: {other}. \
             Only x86_64 and aarch64 are known here, see kernel/build.rs."
        ),
    };

    // Prefer asking dpkg directly for the real multiarch include directory
    // (this is a native build, dpkg-architecture reflects the system
    // actually running clang). Fall back to the conventional GNU triple for
    // the two architectures this crate claims to support if dpkg-architecture
    // isn't available (non-Debian-based system), rather than silently
    // guessing for anything else.
    let multiarch_dir = Command::new("dpkg-architecture")
        .arg("-qDEB_HOST_MULTIARCH")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| match target_arch {
            "x86_64" => "x86_64-linux-gnu".to_string(),
            "aarch64" => "aarch64-linux-gnu".to_string(),
            other => panic!(
                "dpkg-architecture isn't available and there's no fallback multiarch \
                     path known for {other}, see kernel/build.rs."
            ),
        });
    let multiarch_include = format!("-I/usr/include/{multiarch_dir}");

    let entries = std::fs::read_dir("bpf").expect("bpf/ directory missing");
    for entry in entries {
        let path = entry.expect("readdir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("c") {
            continue;
        }

        let stem = path.file_stem().expect("bpf source has no filename").to_string_lossy();
        let out_path = format!("{out_dir}/{stem}.o");

        let status = Command::new("clang")
            .args([
                "-O2",
                "-target",
                "bpf",
                &format!("-D{bpf_arch_define}"),
                "-I/usr/include/bpf",
                &multiarch_include,
                "-c",
            ])
            .arg(&path)
            .arg("-o")
            .arg(&out_path)
            .status()
            .expect("failed to invoke clang, is it installed?");

        assert!(status.success(), "clang failed to compile {}", path.display());
    }
}
