# Repository Guidelines

## Project Overview

Grant-scoped MITM proxy. Terminates client TLS with per-domain leaf certs, swaps format-valid decoy fakes for real secrets only on URI-grant match (`scheme://host[:port]`), redacts real values back to fakes on responses. Non-matching traffic splices byte-identical. Linux has three peer transparent-capture backends behind `--proxy-backend`: `tproxy` (kernel, always compiled in), `tun` (userspace stack), and `ebpf` (cgroup socket hooks, no netfilter). All three are always compiled in on Linux: the backends are chosen at runtime, not at build time.

A cargo workspace: `[workspace] members = ["crates/*"]`, one crate per backend plus `hodor-config`, `hodor-pki`, `hodor-fnox`, `hodor-proxy`, `hodor-compose`, and `hodor-ebpf-programs` (the no_std BPF programs). The root `hodor` package is the binary only.

## Architecture & Data Flow

Startup: `main.rs` → `config::load` (4-layer overlay) → `secrets::resolve` (registry hosts, decoy shapes, fnox values) → `grants::resolve` → `ca::load_or_generate` → `ProxyState::new` (pre-gens leaf certs for exact hosts + one wildcard leaf per `*.`-grant) → `proxy::serve` + the backend `--proxy-backend` selected: `tproxy::run_tproxy`, `tun::run_tun`, `ebpf::run_ebpf`, or neither.
Per-connection: accept → httparse head → `intercept_candidate(host,port)` gates MITM vs splice → SNI sniff (`sni.rs` hand-rolled ClientHello parse) → lock-free leaf-cert lookup (expired rotates on next lookup) → `peek_mode` (HTTP/1 vs H2 preface vs raw) → `relay_guarded` pumps guest chunks through request machine (fake→real) and server chunks through response machine (real→fake). All three capture backends reuse `serve_candidate_stream`, and all three treat the captured destination as the identity. UDP: `tproxy` passes it through (QUIC :443 dropped via nft rule); `tun` runs it through `tun::udp` (DNS to the system resolver, QUIC dropped, others relayed); `ebpf` relays connected UDP unchanged and never sees unconnected `sendto` traffic.
Concurrency: `ProxyState` behind plain `Arc` (write-once, no reload); cert cache is a `DashMap` — keygen on caller, never under lock; per-connection `tokio::spawn`; 10s total pre-auth/dial budgets; capture-loop exclusion by `SO_MARK` fwmark (`tproxy`, `tun`) or cgroup membership plus a PID check (`ebpf`).

## Key Directories

No `tests/` or `scripts/`. All logic in `crates/*`; the root package is only `src/main.rs` (clap CLI, backend dispatch, global allocator):

- `crates/hodor-config/` — `cli.rs` (clap types: `Cli`, `ServeArgs`, `ProxyBackend`), `config.rs` (confique overlay, rule schema, deterministic fake generator `fake_for`), `grants.rs` (`HostPat{Exact,Wildcard,Any}`, `parse_uri_grant`, `uri_match`/`intercept_candidate`/`https_eligible`), `registry.rs` (host registry: bundled `rules/registry.toml` + global `<config-dir>/hodor/rules.d` + project `<root>/.config/hodor/rules.d`). CLI types live here, not in the root crate, because `config::load` consumes `&Cli` and the tests build it with `try_parse_from`.
- `crates/hodor-fnox/` — fnox integration: `layers.rs` (discovery chain), `resolve`, `FnoxSource`, provider-credential export
- `crates/hodor-pki/` — `ca.rs` (`CertAuthority`, `CertCache` (`DashMap`, lazy expiry rotation), `upstream_connector`), `sni.rs` (`extract_sni`, `MAX_HELLO` 16K)
- `crates/hodor-proxy/` — `lib.rs` (`ProxyState`, `serve`, `serve_candidate_stream`, `dial_marked`), `relay.rs` (`relay_guarded`), `sniff.rs`, `substitute/` (`mod.rs` shared scan/replace, `h1.rs` `SecretsMachine`, `h2.rs` `H2Machine` hpack frame walker)
- `crates/hodor-tproxy/` — `tproxy` backend: `IP_TRANSPARENT` listener, nft rules over netfilter netlink (`nft.rs`), policy routes (`route.rs`)
- `crates/hodor-tun/` — `tun` backend: TUN device + userspace smoltcp stack (`tun.rs`), packet classify (`classify.rs`), device plumbing (`phy.rs`), TCP tracker (`tracker.rs`), UDP relay (`udp.rs`), stream adapter (`chan.rs`), policy routes (`route.rs`)
- `crates/hodor-ebpf/` — `ebpf` backend userspace half: `lib.rs` (loader, map layout, attach), `flow.rs` (map lookups), `tcp.rs` (MITM leg), `udp.rs` (relay + janitor). `build.rs` compiles and links the BPF programs into this crate's build output.
- `crates/hodor-ebpf-programs/` — the kernel-side BPF programs (`#![no_std]`): `connect4`, `recvmsg4`, `capture_egress`, and the `CONFIG`/`ORIG_DST`/`FLOW` maps. A workspace member only so `aya-build` can resolve it with `cargo build --package`; it builds for the `bpf` target alone, so **every workspace-wide command excludes it** (`--exclude hodor-ebpf-programs` in `hk.pkl`, the build tasks, `test/rust`, and CI).
- `crates/hodor-compose/` — compose stack generation: `stack.rs`, `paths.rs`, `confine.rs`
- `.mise/tasks/` — the tasks themselves, as executable files (`format`, `clean`, `build/{_default,debug,plugins,release}`, `test/{_default,rust,tun,tproxy,ebpf}`, `demo/{_default,bwrap}`); not configured in `mise.toml`; `test:rust` depends on `build:plugins` and runs the plugin e2e suite with `HODOR_PLUGIN_FIXTURES`
- `integration/` — transparent docker compose demo: client shares hodor's netns (`--proxy-backend tproxy`, no proxy knowledge, fake-only) + bun api (real-token validation, RFC1918 subnet to prove LAN capture); `mise run demo` builds the runtime image and asserts all four substitution/splice scenarios

- `.github/workflows/` — `ci.yml` (format/clippy/nextest gates), `release.yml` (cargo-dist, generated — do not hand-edit), `release-cut.yml` (version bump + git-cliff + cargo-release), `container.yml` (reusable workflow called by release.yml via `post-announce-jobs`; packs release tarballs into runtime-only image)

## Development Commands

**START HERE: `mise tasks`. That command lists every available task — run it first, always, before anything else. It is the entry point to this repo: never guess a task name, never reach past it to raw `cargo`.**

**Mise tasks only — never run raw `cargo` (no `cargo build`, `cargo check`, `cargo clippy`, `cargo nextest`, no single-test runs). The one and only verification is `mise run format`, run bare: no pipes, no redirection, no `tail`, nothing chained, no other gate before or after it.**

**Tasks are executable files under `.mise/tasks/` (nested dirs make namespaced subcommands, e.g. `.mise/tasks/test/rust` → `mise run test:rust`); `mise.toml` holds only tools, env, and settings — no task bodies. So a proposal is a proposal to add one executable file at a specific `.mise/tasks/...` path; make it executable, keep the shebang, and follow the existing files' header/error style.**

**If the task you need does not exist in `mise tasks`, propose it. Say what it would run, which file it would live at, why it is needed, and stop there — do not create the file, do not add it to `mise.toml`, do not work around it with a raw command. Wait for approval.**

```sh
mise tasks        # FIRST: list every available task
mise run format   # the one gate: hk run fix --all, must be green
mise run test     # nextest, whole workspace
mise run test:tun  # live TUN only: needs root, serial
mise run test:tproxy # live TPROXY only: needs root, serial
mise run test:ebpf # live eBPF only: needs root, a cgroup v2 tree, serial
mise run demo      # docker compose integration demo (builds image, needs docker)
hodor serve [--proxy-backend tun|tproxy|ebpf|none] [--ebpf-cgroup PATH] [--listen 127.0.0.1:8080] [--ca-file ...]  # serve is default
hodor fake <ENV> [--pattern '{hex:32}']  # deterministic fake
hodor ca  # generate/load CA, print cert PEM (trust anchor for workload containers)
```

Config precedence: CLI > env (`HODOR_*`) > project (`<root>/.config/hodor.toml`) > global (`$HODOR_CONFIG` or `<config-dir>/hodor/config.toml`). `--proxy-backend`/`HODOR_PROXY_BACKEND`, `--tproxy-allow-root-netns`, and `--ebpf-cgroup` are CLI/env only by design.

## Code Conventions & Common Patterns

- Format: rustfmt edition 2024, `max_width=140`, `tab_spaces=2`, `merge_derives=false`; `cargo sort --grouped` for `Cargo.toml`.
- Lints: `missing_docs` warn (every pub item documented); clippy pedantic/perf/cargo warn; every suppression carries `reason=` and is item-scoped. No crate-level `#![allow]`/`#![expect]` blanket on code we own: fix the lint, or narrow the item's visibility so it stops firing. A crate-level suppression is also brittle under `#[expect]`, which is checked in both directions — it errors when the lint does not fire in every target (e.g. a lint that only fires in `lib test`). gate is `hk.pkl`: sort → rustfmt → `cargo-check` → clippy, each run `--workspace --exclude hodor-ebpf-programs --all-targets`. **`--workspace` matters**: the root package doubles as the workspace root, so a bare `cargo check --all-targets` covers only the root binary and every crate's unit tests would go unchecked.
- Errors: `eyre::Result` everywhere with context strings (`bail!`/`ensure!`); malformed client traffic closes quietly (`Ok(())`), never errors. Framing uncertainty degrades to opaque scan-and-forward, never blocks.
- Async: tokio multi-thread; `tokio::select!` in relay/UDP pumps; `DashMap` cert cache (lock-free reads, keygen on caller); `socket2` for `SO_MARK`.
- Secrets: `secrecy::SecretString`; log label + `Location::{Header,BasicAuth,Body}` only, never values. Test fakes look like `$$_CREDENTIAL_XXX:L`.
- Naming: `snake_case` behavior-descriptive tests (no `test_` prefix, e.g. `precedence_cli_beats_env_beats_project_beats_global`); live tests `tun_live_*`/`tproxy_live_*`/`ebpf_live_*`; scenario modules `h2_tests`, `stack_tests`.
- Grants: `scheme://host[:port]` (`http`/`https`/`tcp`; tcp needs port; hosts exact/`*.`-wildcard/`*`, ASCII case-insensitive).
- eBPF: the map structs (`Config`, `OrigDst`, `FlowKey`) are an ABI with `hodor-ebpf-programs`, so **every byte is explicit, padding included** — a `#[repr(C)]` struct with implicit padding would let insert and lookup disagree on bytes the kernel compares. `crates/hodor-ebpf/src/lib.rs` pins the layouts in a test, and the byte-order helpers (`decode_addr`/`encode_addr`/`decode_port`) exist so the two directions cannot drift.
- Backend dispatch: `src/main.rs` funnels all three capture backends through one `with_capture(listener, state, name, future)` helper, which owns the fail-closed `select!` and the `ctrl_c` abort. Add a backend by adding an arm, not a fourth copy of that block.

## Important Files

| Path | Role |
| --- | --- |
| `Cargo.toml` | workspace root (`members = ["crates/*"]`) + the `hodor` binary package, edition 2024; no cargo features |
| `crates/hodor-config/`, `crates/hodor-fnox/` | config overlay, grant model, registry, CLI types; fnox integration |
| `crates/hodor-proxy/` | proxy core and substitution engine (split across `lib`/`relay`/`sniff`/`substitute`) |
| `crates/hodor-pki/` | PKI + `DashMap` leaf cache, SNI parse |
| `crates/hodor-tproxy/`, `crates/hodor-tun/`, `crates/hodor-ebpf/`, `crates/hodor-ebpf-programs/` | the four capture-related crates: three backend halves plus the no_std BPF programs |
| `rules/registry.toml` | bundled known-host and token-shape registry, overridable per entry |
| `.mise/tasks/`, `mise.toml`, `mise.lock` | tasks as executable files under `.mise/tasks/`; `mise.toml`/`mise.lock` only pin toolchain + env (rust stable, nextest, hk, pkl, hadolint, shellcheck, cargo-sort) |
| `hk.pkl`, `rustfmt.toml`, `.config/nextest.toml` | lint pipeline, format, nextest (retries=3, slow-timeout 30s) |
| `Dockerfile` | runtime-only `ghcr.io/casualjim/bare:libcxx-ssl` + prebuilt binary (no build stage); multi-arch via per-platform digests + manifest merge in `container.yml` |
| `dist-workspace.toml`, `.git-cliff.toml` | cargo-dist release targets (linux amd64+arm64), changelog config |
| `.github/build-setup.yml` | steps dist injects before `dist build`: cmake plus the nightly toolchain and `bpf-linker` the `ebpf` backend's build needs |
| `README.md` | purpose + sanctioned tasks + release flow + acceptance pointer |

## Runtime/Tooling Preferences

Rust-only repo (no Node/Bun). Toolchain Rust 1.98.1 stable via mise; `CARGO_HOME`/`RUSTUP_HOME` sandboxed to `.cache/native/`; `bpf-linker` pinned in `mise.toml` (it links the `bpfel-unknown-none` object, and nightly plus `-Z build-std` builds it — the `bpf` target has no prebuilt `core`). Test runner `cargo-nextest` (mise-pinned). CI mirrors the local gates (`.github/workflows/ci.yml`); `hk` pre-commit remains the fast enforcement. Release flow mirrors remark: CI green on `main` → `release-cut.yml` bumps version (bump:major/minor/patch token in PR/commit), git-cliff writes `CHANGELOG.md`, cargo-release tags; tag triggers `release.yml` (cargo-dist binaries), which calls `container.yml` after announce (downloads release tarballs, packs runtime-only image, pushes to ghcr; asserts the binary carries all three capture markers). Runtime base is chisel rootfs with no shell; policy routing via `rtnetlink`, not `ip`. Env redactions: `*_TOKEN/*_SECRET/*_KEY/*_PASSWORD`.

## Testing & QA

Framework: `cargo-nextest` over inline `#[cfg(test)] mod tests` per file (invoked through `mise run test`, never raw `cargo nextest`); `tokio::test` for async; helpers co-located (`MitmFixture` in `hodor-proxy`, `make_tun` in `hodor-tun`, `lock_env`+`tempdir` in `hodor-config`); deps `pretty_assertions`, `tempfile` only. No `tests/` dir, no snapshots, no coverage tooling, no single-test runs. Live capture tests are `#[ignore]`, run explicitly via `mise run test:tun` / `mise run test:tproxy` / `mise run test:ebpf` (root + `--test-threads=1`); closest end-to-end proofs are `tun_live_tcp_mitm_substitutes` and `tproxy_live_tcp_mitm_substitutes` (fake→real→fake). The unit suite runs once over the whole workspace: there are no cargo features to vary. The eBPF crate's non-live tests cover the byte-order and map-layout invariants, which cannot be exercised without root.
