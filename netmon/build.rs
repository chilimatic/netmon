use std::{env, fs, path::PathBuf};

use anyhow::{Context as _, anyhow};
use aya_build::{Package, Toolchain};

/// Compiles netmon-ebpf to BPF bytecode in OUT_DIR.
/// With AYA_BUILD_SKIP=1 an empty object is written so the userspace code
/// still compiles and its tests run without bpf-linker.
fn main() -> anyhow::Result<()> {
    if matches!(env::var("AYA_BUILD_SKIP").as_deref(), Ok("1" | "true")) {
        let out = PathBuf::from(env::var("OUT_DIR")?).join("netmon");
        if !out.exists() {
            fs::write(&out, []).context("write placeholder eBPF object")?;
        }
    }
    let root_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
        .join("../netmon-ebpf")
        .canonicalize()
        .context("find netmon-ebpf")?;
    let root_dir = root_dir.to_str().ok_or_else(|| anyhow!("non-UTF-8 path"))?;
    println!("cargo:rerun-if-changed={root_dir}/src");
    println!("cargo:rerun-if-changed={root_dir}/../netmon-common/src");
    aya_build::build_ebpf(
        [Package { name: "netmon-ebpf", root_dir, ..Default::default() }],
        Toolchain::default(),
    )
}
