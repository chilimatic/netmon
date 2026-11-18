use which::which;

/// Rebuild the eBPF object when bpf-linker changes.
fn main() {
    if let Ok(bpf_linker) = which("bpf-linker") {
        println!("cargo:rerun-if-changed={}", bpf_linker.display());
    }
}
