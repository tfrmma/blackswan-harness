use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bpf");

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set by cargo");

    let entries = std::fs::read_dir("bpf").expect("bpf/ directory missing");
    for entry in entries {
        let path = entry.expect("readdir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("c") {
            continue;
        }

        let stem = path.file_stem().expect("bpf source has no filename").to_string_lossy();
        let out_path = format!("{out_dir}/{stem}.o");

        // TODO: the x86_64-linux-gnu include path is hardcoded, this only
        // works on x86_64. Needs to branch on target_arch (or shell out to
        // `clang -print-multiarch`) before this can build on arm64.
        let status = Command::new("clang")
            .args([
                "-O2",
                "-target",
                "bpf",
                "-D__TARGET_ARCH_x86",
                "-I/usr/include/bpf",
                "-I/usr/include/x86_64-linux-gnu",
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
