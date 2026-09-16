//! Build glue: compile the eBPF programs for the `bpf` target and make the
//! resulting object part of this crate's build output.
//!
//! `aya-build` shells out to nightly with `-Z build-std`, because the BPF
//! target has no prebuilt `core`. It writes the object to `$OUT_DIR`, which is
//! where `include_bytes_aligned!` in `src/lib.rs` picks it up.

use aya_build::{Package, Toolchain};

fn main() -> Result<(), Box<dyn std::error::Error>> {
  // Emit `cfg(bpf_target_arch=...)` so `aya-ebpf-bindings` selects the right
  // architecture's bindings; without it the bindings crate fails to compile.
  aya_build::emit_bpf_target_arch_cfg()?;
  aya_build::build_ebpf(
    [Package {
      name: "hodor-ebpf-programs",
      root_dir: "crates/hodor-ebpf-programs",
      ..Package::default()
    }],
    Toolchain::Nightly,
  )?;
  Ok(())
}
