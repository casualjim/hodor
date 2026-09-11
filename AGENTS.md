# Repository Guidelines

## Project Overview
Grant-scoped MITM proxy. Terminates client TLS with per-domain leaf certs, swaps format-valid decoy fakes for real secrets only on URI-grant match (`scheme://host[:port]`), redacts real values back to fakes on responses. Non-matching traffic splices byte-identical. Optional `tun` feature adds transparent capture via userspace TCP/IP stack.

## Architecture & Data Flow
Startup: `main.rs` → `config::load` (4-layer overlay) → `secrets::resolve` (registry hosts, decoy shapes, fnox values) → `grants::resolve` → `ca::load_or_generate` → `ProxyState::new` (pre-gens leaf certs for exact hosts + one wildcard leaf per `*.`-grant) → `proxy::serve` + optional `tun::run_tun`.
Per-connection: accept → httparse head → `intercept_candidate(host,port)` gates MITM vs splice → SNI sniff (`sni.rs` hand-rolled ClientHello parse) → lock-free leaf-cert lookup (expired rotates on next lookup) → `peek_mode` (HTTP/1 vs H2 preface vs raw) → `relay_guarded` pumps guest chunks through request machine (fake→real) and server chunks through response machine (real→fake). TUN path reuses `serve_candidate_stream`; UDP relayed directly (DNS→system resolver, QUIC :443 dropped).
Concurrency: `ProxyState` behind plain `Arc` (write-once, no reload); cert cache is a `DashMap` — keygen on caller, never under lock; per-connection `tokio::spawn`; 10s total pre-auth/dial budgets; `SO_MARK` fwmark for TUN loop exclusion.

## Key Directories
No `tests/`, `scripts/`, `docs/`, `examples/`. All logic in `src/*.rs`:
- `src/main.rs` — clap CLI (`serve` default, `fake`, `ca`), wiring
- `src/config.rs` — confique overlay + rule schema + deterministic fake generator (`fake_for`)
- `src/secrets.rs` — host registry (`rules/registry.toml` + `<config-dir>/hodor/rules.d`), rule resolution, fnox value lookup
- `src/grants.rs` — `HostPat{Exact,Wildcard,Any}`, `parse_uri_grant` (structure via `url` crate, `*` via placeholder), `uri_match`/`request_match`/`intercept_candidate`/`https_eligible`
- `src/proxy.rs` — `ProxyState`, `serve`/`handle_conn`/`handle_connect`, `sniff_stream`, `mitm_tls_stream`, `relay_guarded`, `Prefixed`
- `src/substitute.rs` — `SubMachine`/`AnyMachine`, `SecretsMachine` (HTTP/1), `H2Machine` (hpack frame walker)
- `src/ca.rs` — `CertAuthority`, `CertCache` (`DashMap`, lazy expiry rotation), `upstream_connector`
- `src/sni.rs` — `extract_sni`, `MAX_HELLO` 16K
- `src/tun.rs` — `tun` feature only: `TunPhy`, `TcpTracker`, `ChanStream`, `RouteGuard`
- `.mise/tasks/` — ops scripts (`format`, `build`, `test/_default`, `test/rust`, `test/tun`, `demo`)
- `integration/` — transparent docker compose demo: client shares hodor's netns (`--tun` capture, no proxy knowledge, fake-only) + bun api (real-token validation, RFC1918 subnet to prove LAN capture); `mise run demo` builds the runtime image and asserts all four substitution/splice scenarios
- `.github/workflows/` — `ci.yml` (format/clippy/nextest gates), `release.yml` (cargo-dist, generated — do not hand-edit), `release-cut.yml` (version bump + git-cliff + cargo-release), `container.yml` (reusable workflow called by release.yml via `post-announce-jobs`; packs release tarballs into runtime-only image)

## Development Commands
Sanctioned path is mise (runs both feature sets):
```sh
mise run format   # hk run fix --all, must be green
mise run test     # nextest default features, then --features tun
mise run test:tun # live TUN only: needs root, serial
mise run demo      # docker compose integration demo (builds image, needs docker)
cargo nextest run substitute::tests::raw_mode_skips_unequal_length  # single test
cargo build --release --features tun --target <triple>  # release build shape (CI builds once; Dockerfile never compiles)
hodor serve [--tun] [--listen 127.0.0.1:8080] [--ca-file ...]  # serve is default
hodor fake <ENV> [--pattern '{hex:32}']  # deterministic fake
hodor ca  # generate/load CA, print cert PEM (trust anchor for workload containers)
```
Config precedence: CLI > env (`HODOR_*`) > project (`<root>/.config/hodor.toml`) > global (`$HODOR_CONFIG` or `<config-dir>/hodor/config.toml`). `--tun`/`HODOR_TUN` is CLI/env only by design.

## Code Conventions & Common Patterns
- Format: rustfmt edition 2024, `max_width=140`, `tab_spaces=2`, `merge_derives=false`; `cargo sort --grouped` for `Cargo.toml`.
- Lints: `missing_docs` warn (every pub item documented); clippy pedantic/perf/cargo warn; `#[allow]` must carry `reason=`; gate is `hk.pkl`: sort → rustfmt → `cargo-check` → `clippy --all-targets --features tun -- -D warnings`.
- Errors: `eyre::Result` everywhere with context strings (`bail!`/`ensure!`); malformed client traffic closes quietly (`Ok(())`), never errors. Framing uncertainty degrades to opaque scan-and-forward, never blocks.
- Async: tokio multi-thread; `tokio::select!` in relay/UDP pumps; `DashMap` cert cache (lock-free reads, keygen on caller); `socket2` for `SO_MARK`.
- Secrets: `secrecy::SecretString`; log label + `Location::{Header,BasicAuth,Body}` only, never values. Test fakes look like `$$_CREDENTIAL_XXX:L`.
- Naming: `snake_case` behavior-descriptive tests (no `test_` prefix, e.g. `precedence_cli_beats_env_beats_project_beats_global`); live tests `tun_live_*`; scenario modules `h2_tests`, `stack_tests`.
- Grants: `scheme://host[:port]` (`http`/`https`/`tcp`; tcp needs port; hosts exact/`*.`-wildcard/`*`, ASCII case-insensitive).

## Important Files
| Path | Role |
|---|---|
| `Cargo.toml` | single crate `hodor` v0.1.0, edition 2024; sole feature `tun` |
| `src/main.rs`, `src/config.rs`, `src/grants.rs` | entry, config overlay, grant model |
| `src/proxy.rs`, `src/substitute.rs` | proxy core, substitution engine (largest module) |
| `src/ca.rs`, `src/sni.rs`, `src/tun.rs` | PKI + `DashMap` leaf cache, SNI parse, transparent capture |
| `rules/registry.toml` | bundled known-host and token-shape registry, overridable per entry |
| `mise.toml`, `mise.lock` | pinned toolchain (rust stable, nextest, hk, pkl, hadolint, shellcheck, cargo-sort) |
| `hk.pkl`, `rustfmt.toml`, `.config/nextest.toml` | lint pipeline, format, nextest (retries=3, slow-timeout 30s) |
| `Dockerfile` | runtime-only `ghcr.io/casualjim/bare:libcxx-ssl` + prebuilt binary (no build stage); multi-arch via per-platform digests + manifest merge in `container.yml` |
| `dist-workspace.toml`, `.git-cliff.toml` | cargo-dist release targets (linux amd64+arm64, `--features tun`), changelog config |
| `README.md` | purpose + sanctioned tasks + release flow + acceptance pointer |

## Runtime/Tooling Preferences
Rust-only repo (no Node/Bun). Toolchain Rust 1.98.1 stable via mise; `CARGO_HOME`/`RUSTUP_HOME` sandboxed to `.cache/native/`. Test runner `cargo-nextest` (mise-pinned). CI mirrors the local gates (`.github/workflows/ci.yml`); `hk` pre-commit remains the fast enforcement. Release flow mirrors remark: CI green on `main` → `release-cut.yml` bumps version (bump:major/minor/patch token in PR/commit), git-cliff writes `CHANGELOG.md`, cargo-release tags; tag triggers `release.yml` (cargo-dist binaries), which calls `container.yml` after announce (downloads release tarballs, packs runtime-only image, pushes to ghcr). Runtime base is chisel rootfs with no shell; policy routing via `rtnetlink`, not `ip`. Env redactions: `*_TOKEN/*_SECRET/*_KEY/*_PASSWORD`.

## Testing & QA
Framework: `cargo-nextest` over inline `#[cfg(test)] mod tests` per file; `tokio::test` for async; helpers co-located (`MitmFixture` in `proxy.rs`, `test_iface` in `tun.rs`, `lock_env`+`tempdir` in `config.rs`); deps `pretty_assertions`, `tempfile` only. No `tests/` dir, no snapshots, no coverage tooling. Live TUN tests are `#[ignore]`, gated by `HODOR_TEST_TUN=1` + root + `--test-threads=1` (`mise run test:tun`); closest end-to-end proof is `tun_live_tcp_mitm_substitutes` (fake→real→fake).
