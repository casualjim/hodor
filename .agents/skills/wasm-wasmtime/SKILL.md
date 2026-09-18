---
name: wasm-wasmtime
description: WebAssembly runtime skill using wasmtime. Use when running WASM modules with wasmtime CLI, working with WASI (wasip1/wasip2/wasip3 — WASI 0.1/0.2/0.3), using the component model, composing components with wac, embedding wasmtime in Rust applications, limiting execution with fuel metering, or debugging WASM with DWARF in wasmtime. Activates on queries about wasmtime, WASI, WASI 0.2/0.3, wasip3, WASM component model, wasmtime embedding, WIT interfaces, wac/wstd, fuel metering, or server-side WebAssembly.
---

# wasmtime — Server-Side WASM Runtime

## Purpose

Guide agents through wasmtime: running WASM modules from the CLI, WASI APIs (wasip1/wasip2/wasip3), the component model with WIT interfaces, composing components with `wac`, the `wstd` async Rust stdlib for components, embedding wasmtime in Rust applications, fuel metering for sandboxed execution, and debugging WASM with DWARF debug info.

## Triggers

- "How do I run a WASM file with wasmtime?"
- "How does WASI work with wasmtime?" / "What is wasip2 / wasip3 / WASI 0.2 / WASI 0.3?"
- "How do I embed wasmtime in my Rust application?"
- "What is the WebAssembly component model?"
- "How do I compose WebAssembly components?" (wac)
- "How do I limit WASM execution with fuel?"
- "How do I debug a WASM module in wasmtime?"

## WASI version landscape (wasip1 / wasip2 / wasip3)

WASI has three snapshots. Rust bindings live in the `wasi` repo (formerly `wasi-rs`): https://github.com/bytecodealliance/wasi

| WASI | Std name | Target | Crate | Status |
|---|---|---|---|---|
| 0.1 | wasip1 (`wasi_snapshot_preview1` syscalls) | `wasm32-wasip1` | `wasip1` (1.x) | maintenance mode; standard ceased |
| 0.2 | wasip2 (component model, `wasi:cli/command`, `wasi:http/proxy` worlds) | `wasm32-wasip2` | `wasip2` (2.x) | stable; default |
| 0.3 | wasip3 (`wasi:cli/command`, `wasi:http/service` worlds) | `wasm32-wasip3` | `wasip3` (0.x) | experimental; in development |

- `wasi` crate (0.14.x) = lightweight reexport of latest stable (currently wasip2). Prefer the explicit `wasip2`/`wasip3` crates to pin your WASI version.
- `wasip2` 2.0.0+wasi-0.2.12, `wasip3` 0.9.0+wasi-0.3.0 (versions carry `+wasi-<spec>` build metadata).
- `wasip3` requires Rust ≥ 1.90; `wasm32-wasip3` target exists in rustc 1.97+. Both `wasip2` and `wasip3` crates target `wasm32-wasip2` today (the p3 crate can also be used with the `wasm32-wasip3` target once installed: `rustup target add wasm32-wasip3`).
- wasip3 changes vs 0.2: `wasi:http/service` world supersedes `wasi:http/proxy`; async-capable `wasi:io`, streams with futures, `@since(version = 0.3.0)` features in WIT.
- **wasmtime** supports wasip1 (preview1, implemented on the wasip2 engine by default), wasip2 (stable, default), and wasip3 (experimental, unstable, incomplete — see `wasmtime_wasi::p3`; linked only when the p3 option is on).

## Workflow

### 1. wasmtime CLI

```bash
# Install
curl https://wasmtime.dev/install.sh -sSf | bash

# Run a WASM module (core module with wasip1, or a component with wasip2/wasip3)
wasmtime hello.wasm

# Run with WASI arguments
wasmtime prog.wasm -- arg1 arg2

# Pre-open directories (WASI filesystem sandbox)
wasmtime --dir /tmp::/ prog.wasm    # map host /tmp to WASI root

# Pass environment variables
wasmtime --env HOME=/home/user prog.wasm

# Invoke specific exported function
wasmtime run --invoke add math.wasm 3 4

# Explore / compile ahead-of-time
wasmtime explore math.wasm          # interactive explorer
wasmtime compile prog.wasm -o prog.cwasm
wasmtime run prog.cwasm
```

Flag groups: `-W` semantics (wasm proposals), `-S` WASI, `-O` optimize, `-C` codegen, `-D` debug, `-R` record — each `KEY[=VAL]` comma-separated (e.g. `-S http=y`, `-W gc=y`). Run `wasmtime run -S help` / `-W help` / `-D help` to list options.

```bash
# WASI options (current syntax, wasmtime 25+)
wasmtime -S http=y prog.wasm                    # enable wasi-http (components only)
wasmtime -S p3=y prog.wasm                      # enable WASIp3 (default on in async builds)
wasmtime -S inherit-network=y prog.wasm          # guest gets host network
wasmtime -S max-resources=1024 prog.wasm        # cap resources
wasmtime -S preview2=n prog.wasm                 # legacy wasip1-only implementation

# wasm proposal toggles
wasmtime -W gc=y prog.wasm
wasmtime -W fuel=1000000 prog.wasm              # CLI fuel metering
```

`wasmtime inspect` was removed — use `wasm-tools` for module inspection (see §6).

### 2. WASI preview2 / preview3 APIs

WASI 0.2 (wasip2) is a capability-based API set defined in WIT for the component model:

```bash
# Key WASI interfaces (WIT)
# wasi:cli — stdin/stdout/stderr, environment, args, exit
# wasi:filesystem — file and directory access
# wasi:sockets — TCP/UDP networking, name lookup
# wasi:http — HTTP client/server (proxy world in 0.2, service world in 0.3)
# wasi:random — secure random numbers
# wasi:clocks — system and monotonic clocks
# wasi:io — streams/poll (the async foundation; grew futures in 0.3)
```

WASIp3 (0.3) keeps the same package layout but evolves the interfaces: `wasi:cli/command` and `wasi:http/service` become the standard worlds, and `wasi:io`/`wasi:http` gain async/futures-style APIs (`@since(version = 0.3.0)`).

### 3. Embedding wasmtime in Rust

```toml
# Cargo.toml — use the current stable version (49 as of late 2026)
[dependencies]
wasmtime = "49"
wasmtime-wasi = "49"
anyhow = "1"
```

```rust
use wasmtime::*;
use wasmtime_wasi::WasiCtxBuilder;

fn main() -> anyhow::Result<()> {
    // Create engine with default config
    let engine = Engine::default();

    // Load and compile WASM module
    let module = Module::from_file(&engine, "prog.wasm")?;

    // Set up WASI context
    let wasi = WasiCtxBuilder::new()
        .inherit_stdio()
        .inherit_env()
        .preopened_dir("/tmp", "/")?
        .build();

    // Create a store (holds WASM state)
    let mut store = Store::new(&engine, wasi);

    // Instantiate the module
    let instance = Instance::new(&mut store, &module, &[])?;

    // Call an exported function
    let add = instance.get_typed_func::<(i32, i32), i32>(&mut store, "add")?;
    let result = add.call(&mut store, (3, 4))?;
    println!("Result: {result}");

    Ok(())
}
```

For components use `wasmtime::component::{Component, Linker}` with `wasmtime_wasi::p2::add_to_linker` / `p3::add_to_linker` (see §5). WASIp3 embedding support lives in `wasmtime_wasi::p3` behind the crate's `p3` feature — experimental.

### 4. Fuel metering — CPU limiting

Fuel metering limits the number of WASM instructions executed, preventing runaway or malicious code:

```rust
use wasmtime::*;

let mut config = Config::default();
config.consume_fuel(true);    // enable fuel consumption

let engine = Engine::new(&config)?;
let module = Module::from_file(&engine, "untrusted.wasm")?;

let mut store = Store::new(&engine, ());
store.set_fuel(1_000_000)?;   // allow 1M instructions

let instance = Instance::new(&mut store, &module, &[])?;
let run = instance.get_typed_func::<(), ()>(&mut store, "run")?;

match run.call(&mut store, ()) {
    Ok(_) => println!("Completed, fuel remaining: {}", store.get_fuel()?),
    Err(e) if e.to_string().contains("all fuel consumed") => {
        println!("Timed out (fuel exhausted)");
    }
    Err(e) => eprintln!("Error: {e}"),
}
```

CLI equivalent: `wasmtime -W fuel=1000000 prog.wasm`.

### 5. Component model, WIT, and composition (wac)

The component model adds typed interface definitions (WIT) on top of core WASM:

```wit
// math.wit — interface definition
package example:math@1.0.0;

interface calculator {
    add: func(a: s32, b: s32) -> s32;
    sqrt: func(x: f64) -> f64;
}

world math-world {
    export calculator;
}
```

```bash
# Install component toolchain
cargo install wasm-tools cargo-component wac-cli

# Create a Rust component
cargo component new --lib math-component
# Implement the WIT interface in src/lib.rs

# Build component
cargo component build --release

# Run with wasmtime
wasmtime run math-component.wasm
```

```rust
// Embed a component in Rust
use wasmtime::component::*;

wasmtime::component::bindgen!({
    world: "math-world",
    path: "math.wit",
});

let component = Component::from_file(&engine, "math.wasm")?;
let (calculator, _) = MathWorld::instantiate(&mut store, &component, &linker)?;
let result = calculator.call_add(&mut store, 3, 4)?;
```

**Composing components with `wac`** (wac-cli: `plug`, `compose`, `parse`, `resolve`, `targets`): the WAC language (a declarative superset of WIT) wires component exports into other components' imports:

```wac
// composition.wac — plug name.wasm's `name` export into greeter.wasm's import
package example:composition;

let n = new example:name {};
let greeter = new example:greeter {
    name: n.name,
};
```

```bash
wac compose composition.wac -o greeter-app.wasm
wasmtime run greeter-app.wasm
```

### 6. WASM debugging with DWARF

```bash
# Build WASM with debug info (Rust)
cargo build --target wasm32-wasip2    # debug profile includes DWARF by default

# Full DWARF stack traces
WASMTIME_BACKTRACE_DETAILS=1 wasmtime prog.wasm

# Embedding: config.debug_info(true) or CLI: -D debug-info=y
wasmtime -D debug-info=y prog.wasm

# GDB stub (remote debugging): -g
wasmtime -g 127.0.0.1:12345 prog.wasm

# wasm-tools for inspection (wasmtime inspect was removed)
wasm-tools print prog.wasm | head -50     # disassemble to WAT
wasm-tools validate prog.wasm             # validate WASM binary
wasm-tools component wit prog.wasm       # show component's WIT interfaces
wasm-tools metadata show prog.wasm       # show custom sections
```

### 7. WASM GC (garbage-collected objects)

WASM GC proposal adds struct and array types with managed allocation:

```wat
;; GC-enabled module (toolchain dependent)
(struct $point (field (mut f32) x) (field (mut f32) y))
```

```bash
# wasm-tools with GC support
wasm-tools validate --features gc module.wasm
wasmtime -W gc=y module.wasm
```

In embedding, `config.wasm_gc(true)`. Use `struct.new`, `array.new`, `struct.get`, `array.get` instructions in WAT or compiled output.

### 8. WASM threads and shared memory

```bash
# Core wasm threads + shared memory are enabled by default in wasmtime
# (clang/Rust wasm32-wasip1-threads): atomics, i32.atomic.*, memory.atomic.wait/notify
wasmtime run prog.wasm
```

**Note:** *wasi-threads support was removed from wasmtime* (`support for wasi-threads has been removed from Wasmtime`). The core `threads` proposal (shared memory, atomics) remains on by default. Component-model threading (🧵 in the spec) is experimental: `-W component-model-threading=y`. Toggle core threads with `-W threads=y/n`.

### 9. WASM exception handling

```wat
(try (do $exn)
  (throw $exn)
  (catch $exn (local.get 0) (return)))
```

Exception handling is enabled by default in current wasmtime releases (`wasmtime -W exceptions=y`, `config.wasm_exceptions(true)` in embedding). Replaces longjmp-style Emscripten patterns with native `try/catch/throw` in WASM.

### 10. Rust targets — which WASI to use

| Rust target | Use crate | Notes |
|---|---|---|
| `wasm32-wasip1` | `wasip1` | legacy `wasi_snapshot_preview1`; maintenance |
| `wasm32-wasip2` | `wasip2` (or `wasi` reexport) | stable, component model, `wasi:cli/command` |
| `wasm32-wasip3` | `wasip3` | experimental; `WASMTIME`-hosted, needs wasmtime wasip3 support |

Migrate from wasip1 to wasip2 by regenerating with `cargo component` + wasm-tools and switching the target + crate. Standard library support: `wasm32-wasip1` is tier-2/tier-1 std; `wasm32-wasip2` has std support; `wasm32-wasip3` std support is newer (rustc 1.90+).

### 11. wstd — async std for components (experimental)

`wstd` (https://github.com/bytecodealliance/wstd, crates.io `wstd` 0.6.x) is a minimal async Rust standard library for Wasm components + WASI 0.2: `wstd::io`, `wstd::net`, `wstd::http`, `wstd::time`, `wstd::runtime`, plus an `axum` adapter. Builds with the `wasm32-wasip2` target. Use it to write async component apps before tokio/smol/async-std land wasm-component support:

```bash
cargo add wstd
cargo build --target wasm32-wasip2
```

### 12. Performance configuration

```rust
// High-performance embedding config
let mut config = Config::default();
config.cranelift_opt_level(OptLevel::SpeedAndSize);
config.parallel_compilation(true);
config.cache_config_load_default()?;    // disk cache for compiled modules

// Ahead-of-time compilation for production
// 1. Pre-compile in build pipeline
let serialized = module.serialize()?;
std::fs::write("prog.cwasm", &serialized)?;

// 2. Load pre-compiled at runtime (zero compilation cost)
let module = unsafe { Module::deserialize_file(&engine, "prog.cwasm")? };
```

## Related skills

- Use `skills/runtimes/wasm-emscripten` for compiling C/C++ to WASM for browser/WASI
- Use `skills/rust/rust-async-internals` for async patterns in wasmtime Rust embedding
- Use `skills/runtimes/binary-hardening` for sandboxing considerations with WASM
