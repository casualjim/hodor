# hodor

hodor is a grant-scoped MITM proxy that swaps a workload's format-valid decoy credential for the real value only on hosts you allow.

A workload points its HTTP proxy setting at hodor, or hodor captures its traffic transparently with `--proxy-backend`. Three backends, peers, chosen by mechanism: `tproxy` lets the kernel redirect TCP (nftables plus policy routing; UDP passes through) and `tun` runs a TUN device and an in-process TCP/IP stack, which also relays UDP itself. `ebpf` uses cgroup socket hooks — no netfilter at all — and captures TCP plus connected UDP (relayed, not substituted). Either way the workload holds a decoy credential, never the real one. The decoy is format-valid, so a tool that checks the shape of a token accepts it.

When a connection's host and port match an allow entry, hodor terminates TLS with a per-domain leaf certificate signed by its own CA. It replaces each decoy with its real value in headers, in basic auth, and in bodies, for both HTTP/1 and HTTP/2. On the response, it replaces real values with the decoy again, so the client sees only the decoy.

Every other connection is spliced through byte for byte. hodor does not terminate TLS on those connections, and the client sees the real upstream certificate.

That split is the point. A leaked or exfiltrated credential is the decoy. A request to any host outside the allow list carries the decoy, so the upstream rejects it. The real value appears only on the wire to a host you named.

## Install

**From a release** (Linux, amd64 and arm64), with the installer script:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/casualjim/hodor/releases/latest/download/hodor-installer.sh | sh
```

**With mise**, which installs the release tarball for your platform:

```sh
mise use github:casualjim/hodor
```

Or download a tarball from [the releases page](https://github.com/casualjim/hodor/releases) and put `hodor` on your `PATH`.

**As a container**: `ghcr.io/casualjim/hodor`. The image is runtime-only, entrypoint `hodor`, default command `serve`.

```sh
docker run --rm ghcr.io/casualjim/hodor:latest fake GH_TOKEN
```

**From source**: clone, then build with a recent stable Rust toolchain (the crate uses edition 2024; all three Linux capture backends compile in unconditionally):

```sh
git clone https://github.com/casualjim/hodor
cd hodor
cargo build --release
```

The `ebpf` backend additionally needs a nightly toolchain (the BPF target has no prebuilt `core`, so `aya-build` uses `-Z build-std`) and [`bpf-linker`](https://github.com/aya-rs/bpf-linker) to link the programs; both are pinned in `mise.toml`, so `mise run build` provides them.

## Try it in ten minutes

The [tutorial](docs/user/tutorial.md) walks one request through hodor and shows the swap from both sides: the client sends `Bearer fd0c437df7ae...`, the upstream receives `Bearer real-secret-value-xyz`, and the response carries the decoy back. Then it repeats the trip over HTTPS so you exercise the CA trust step every real deployment needs.

## The shape of a config

```toml
[proxy]
listen = "127.0.0.1:8080"

[rules.github_token]
env = "GITHUB_TOKEN"          # decoy seed, registry key, fnox key
allow = ["https://api.github.com"]
```

Start the proxy, hand the workload its decoy, and the rule is live:

```sh
hodor serve
hodor fake GITHUB_TOKEN    # the value the workload holds
```

`env = "GITHUB_TOKEN"` alone is a complete rule when the bundled known-host registry knows the name: the registry supplies the hosts and the decoy shape, and [fnox](https://fnox.jdx.dev) supplies the real value at serve time (age, 1Password, Vault, Bitwarden, AWS Secrets Manager, the OS keychain, and the rest of its provider catalog; no fnox binary needed).

## Documentation

Everything lives under [docs/user](docs/user/README.md), arranged by what you need:

- [Tutorial](docs/user/tutorial.md) — learn it, first time.
- How-to guides — [confine a workspace](docs/user/how-to/confine-a-workspace.md) (run a coding agent with decoys only), [capture traffic transparently](docs/user/how-to/capture-traffic-transparently.md), [get values from fnox](docs/user/how-to/get-values-from-fnox.md), [extend the registry](docs/user/how-to/extend-the-registry.md), [trust the CA](docs/user/how-to/trust-the-ca.md).
- Reference — [CLI](docs/user/reference/cli.md), [configuration](docs/user/reference/configuration.md), [allow entries](docs/user/reference/allow-entries.md), [decoy patterns](docs/user/reference/decoy-patterns.md), [registry](docs/user/reference/registry.md).
- Explanation — [how hodor works](docs/user/explanation/how-it-works.md), [the security model](docs/user/explanation/security-model.md) (what it defends against and what it does not).

Two runnable examples ship in the repository:

- [examples/agentic-devenv](examples/agentic-devenv/README.md) — a workspace to confine with `hodor up`: one hodor container, one agent container holding only decoys, transparent capture, and real values that stay in fnox.
- [integration](integration/README.md) — the compose demo behind `mise run demo`, asserting four substitution scenarios and one splice scenario.

## Where the limits are

hodor matches the request authority, not the path. A workload that hashes or signs the credential before sending defeats substitution, and the upstream rejects the request. A `*` grant host matches any destination. A client must trust hodor's CA to reach a granted HTTPS host. Transparent capture needs root and Linux; the `tproxy` backend needs `CAP_NET_ADMIN`, the `tun` backend a TUN device, and the `ebpf` backend `CAP_BPF` + `CAP_NET_ADMIN`, kernel 5.15, and IPv4. [The security model](docs/user/explanation/security-model.md) states each of these with its consequence.

## Contributing

Read [AGENTS.md](AGENTS.md) before you change the code.

License: Apache-2.0.
