# hodor

hodor is a grant-scoped MITM proxy that swaps a workload's format-valid decoy credential for the real value only on hosts you allow.

## How it works

A workload points its HTTP proxy setting at hodor, or hodor captures its traffic with `--tproxy`. Either way the workload holds a decoy credential, never the real one. The decoy is format-valid, so a tool that checks the shape of a token accepts it.

When a connection's host and port match an allow entry, hodor terminates TLS with a per-domain leaf certificate signed by its own CA. It replaces each decoy with its real value in headers, in basic auth, and in bodies, for both HTTP/1 and HTTP/2. On the response, it replaces real values with the decoy again, so the client sees only the decoy.

Every other connection is spliced through byte for byte. hodor does not terminate TLS on those connections, and the client sees the real upstream certificate.

That split is the point. A leaked or exfiltrated credential is the decoy. A request to any host outside the allow list carries the decoy, so the upstream rejects it. The real value appears only on the wire to a host you named.

## Install

There are no git tags yet, so there is no release, no published container image, and no download URL. Build from source.

```sh
git clone https://github.com/casualjim/hodor
cd hodor
cargo build --release
```

The binary lands at `target/release/hodor`. The crate uses edition 2024, so build with a recent stable Rust toolchain.

Transparent capture is compiled in on Linux; no cargo feature is needed.

```sh
cargo build --release
```

When releases are published, they carry Linux binaries for amd64 and arm64 plus a container image. The image holds a prebuilt binary. Its entrypoint is `hodor` and its default command is `serve`.

## Quickstart

This walkthrough sends one request through hodor and shows the swap from both sides. You run a local upstream that records the `Authorization` header, send the decoy through the proxy, and check what the upstream received.

Put `target/release/hodor` on your `PATH`, or replace `hodor` with `./target/release/hodor` in the commands below.

Write the config file.

```toml
[proxy]
listen = "127.0.0.1:8080"
ca_file = "ca.pem"

[rules.demo]
env = "DEMO_TOKEN"
value = "real-secret-value-xyz"
allow = ["http://127.0.0.1:8000"]
```

Get the decoy for `DEMO_TOKEN`.

```sh
hodor fake DEMO_TOKEN
```

```
fd0c437df7ae3abca3e37d89840b4503
```

Save this as `upstream.py`. It records the header it receives and echoes it in the response body.

```python
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
  def do_GET(self):
    seen = self.headers.get("Authorization", "<none>")
    with open("seen.txt", "w") as f:
      f.write(seen)
    body = ("upstream saw: " + seen).encode()
    self.send_response(200)
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)

  def log_message(self, *args):
    pass


HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
```

Start the upstream.

```sh
python3 upstream.py
```

Start the proxy in a second terminal.

```sh
hodor serve --config hodor.toml
```

hodor logs the listen address and the grant count.

```
serving, listen: 127.0.0.1:8080, grants: 1
```

Send one request with the decoy, from a third terminal.

```sh
curl -x http://127.0.0.1:8080 http://127.0.0.1:8000/ \
  -H 'Authorization: Bearer fd0c437df7ae3abca3e37d89840b4503'
```

The client sees the decoy.

```
upstream saw: Bearer fd0c437df7ae3abca3e37d89840b4503
```

The upstream received the real value.

```sh
cat seen.txt
```

```
Bearer real-secret-value-xyz
```

To reach a granted `https://` host, the client must trust hodor's CA. Run `hodor ca` to write the CA file and print the certificate. It also writes `ca.crt`, the certificate on its own, and `ca.key`, the private key on its own, beside it. Add the certificate to the client's trust store. A client that does not trust the CA fails the TLS handshake.

## Rules

A rule wires an environment name to the hosts it may reach, the decoy shape the client sees, and where the real value comes from.

`[rules.<label>]` replaces the old `[secrets.<label>]` table. A leftover `[secrets]` table is ignored silently, with no migration shim, so rename it to `[rules]`.

```toml
[rules.gh]
env        = "GITHUB_TOKEN"        # required: decoy seed, registry key, fnox key
value      = "..."                 # optional: inline real value
fnox_key   = "..."                 # optional: fnox secret name, default = env
allow      = ["https://ghe.corp"]  # optional: unions with registry hosts
pattern    = "..."                 # optional: overrides the registry pattern
registry   = false                 # optional: skip registry hosts
if_missing = "error"               # "error" (default) | "warn" | "ignore"
```

`env = "GITHUB_TOKEN"` alone is enough: the registry supplies the hosts and the decoy shape.

## Known-host registry

hodor ships a table of known services in `rules/registry.toml`: the environment names each one uses, its API hosts, and its token shape. Override it from the global `<config-dir>/hodor/rules.d/*.toml` (beside the global config file) or the project `<project-root>/.config/hodor/rules.d/*.toml`, both loaded in filename order; project entries override global ones, which override the bundled table:

```toml
[providers.github]
env      = ["GITHUB_TOKEN"]
hosts    = ["https://api.github.com", "https://ghe.corp.example"]
pattern  = "ghp_ghe_{hex:32}"
contains = ["gh_"]
replace  = false

[names.GH_ENTERPRISE_TOKEN]
hosts = ["https://ghe.corp.example"]
```

`replace = true` discards what earlier layers declared for those names. `contains` matches environment-name substrings and selects a decoy shape only, never hosts. `hodor fake <ENV>` uses the same table, so a custom rule's decoy can be previewed without running a proxy.

## Values from fnox

When a rule has no inline `value`, hodor resolves it through [fnox](https://fnox.jdx.dev), which reaches age, 1Password, AWS Secrets Manager, Vault, Bitwarden, the OS keychain, and the rest of its provider catalog. hodor embeds `fnox-core`; no fnox binary is needed.

The fnox source is fnox's own discovery chain with one level added. Values resolve from least to most specific: fnox's global config (`$FNOX_CONFIG_DIR/config.toml`), then `<config-dir>/hodor/fnox.toml`, then the upward `fnox.toml` walk, per workspace. The middle level belongs to hodor, for secrets that are global here but not global for fnox. It reads `fnox.local.toml` when no profile is active and `fnox.<profile>.toml` per active profile otherwise, so `$FNOX_PROFILE` picks the file standing in for the local slot. A key fnox does not declare follows the rule's `if_missing`; a key it declares but cannot resolve is a startup error.

Embedding `fnox-core` brings rustls's `ring` feature into the build, so both crypto backends are compiled and `ClientConfig::builder()` can no longer select a provider on its own. Any new entry point must call `ca::install_crypto_provider()` first, exactly as `main` does.

`Cargo.toml` pins `keepass = "=0.13.22"` for now. keepass 0.13.23 and later declare an `aes` range with an upper bound only (`<0.9.3`), which resolves to aes 0.8.4 and breaks keepass's own cbc and cipher traits. When a keepass release admits a 0.9.x `aes` again, bump the pin, run bare `mise run --force test:rust`, then delete the pin. `fnox-core` itself stays on a caret requirement (`"1.33"`), deliberately, so a future release can carry the fix.

## Configuration layers

hodor reads four layers. A higher layer wins.

1. CLI flags, `--listen`, `--ca-file`, and `--config`.
2. Environment variables, `HODOR_LISTEN`, `HODOR_CA_FILE`, `HODOR_CONFIG`, and `HODOR_TPROXY`.
3. The project file at `<workspace root>/.config/hodor.toml`.
4. The global file at `$HODOR_CONFIG` or `<config-dir>/hodor/config.toml`.

hodor finds the workspace root by walking up from the working directory. `--config <FILE>` replaces the project file.

`[rules]` merges by label. If the project file and the global file both define `[rules.demo]`, the project entry replaces the global entry.

## Configuration keys

`[proxy]`:

| Key | Default | Environment | Purpose |
| --- | --- | --- | --- |
| `listen` | `127.0.0.1:8080` | `HODOR_LISTEN` | Address the proxy listens on. |
| `ca_file` | `<config-dir>/hodor/ca.pem` | `HODOR_CA_FILE` | Path to the CA file, which holds the certificate followed by the key. `hodor ca` also writes `ca.crt` and `ca.key` beside it. |

`[rules.<label>]`:

| Key | Required | Purpose |
| --- | --- | --- |
| `env` | yes | Environment variable name. Seeds the decoy, keys the registry lookup, and defaults the fnox key. |
| `value` | no | Inline real secret value. Wins over fnox. |
| `fnox_key` | no | fnox secret name. Defaults to `env`. |
| `allow` | no | List of allow entries. Unions with the hosts the registry supplies. |
| `pattern` | no | Decoy pattern, overriding the registry. |
| `registry` | no | Whether this rule uses registry hosts. Default `true`. |
| `if_missing` | no | `error` (default), `warn`, or `ignore`. |

`[agents.<name>]`:

Every directory under `<config-dir>/hodor/agents/` mounts into the agent container at the location that agent reads its own configuration from by default, so nothing has to set a config-directory variable. The built-in table covers `amazon-q`, `amp`, `auggie`, `claude`, `cline`, `codebuddy`, `codebuff`, `codex`, `continue`, `copilot`, `crush`, `cursor`, `deepagents`, `droid`, `dsh`, `forge`, `gemini`, `goose`, `gptme`, `grok`, `hermes`, `iflow`, `junie`, `kilo`, `kimi`, `kimi-code`, `kiro`, `mimo-code`, `muse-code`, `omp`, `open-interpreter`, `openclaw`, `openhands`, `opencode`, `pi`, `qoder`, `qwen`, `roo`, `trae`, `vibe`, and `warp`. A directory whose name no entry covers mounts nothing. Entries also carry the common CLI-name spellings, so `claude-code`, `codex-cli`, `gemini-cli`, `grok-build`, `muse`, `qwen-code`, `roo-code`, `mimo`, `factory`, `augment`, `workbuddy`, and `kiro-cli` all resolve.

| Key | Required | Purpose |
| --- | --- | --- |
| `config_dir` | yes | Container path the directory mounts at. `{home}` expands to `[workspace] home`. |

```toml
[agents.trae]
config_dir = "{home}/.trae"
```

An entry overrides a built-in path for that name, or adds a name the table does not carry. The mount is writable, so what the agent writes there lands under `<config-dir>/hodor/agents/<name>` on the host.

`HODOR_*` environment variables:

| Variable | Effect |
| --- | --- |
| `HODOR_LISTEN` | Sets `[proxy] listen`. |
| `HODOR_CA_FILE` | Sets `[proxy] ca_file`. |
| `HODOR_CONFIG` | Sets the global config file path. |
| `HODOR_TPROXY` | Same as `--tproxy`. CLI and environment only. |
| `HODOR_TPROXY_ALLOW_ROOT_NETNS` | Same as `--tproxy-allow-root-netns`: acknowledges unscoped capture rules in the current network namespace. |

hodor validates the config at startup. It rejects two rules that share an env name, an empty `env` or `value`, a malformed allow entry, and a malformed pattern. A `*` host in an allow entry logs a warning that the grant matches any host and the secret is at risk of exfiltration.

## Allow entries

An allow entry has the form `scheme://host[:port]`.

- Schemes are `http`, `https`, and `tcp`.
- The default port is 80 for `http` and 443 for `https`. A `tcp` entry needs an explicit port.
- A host is an exact name, a `*.`-prefixed suffix, or `*`. A `*.`-prefixed suffix matches subdomains only and never the apex. `*` matches any host. Matching is ASCII case-insensitive.
- An entry is authority only. hodor rejects a path, a query, or userinfo.
- An IPv6 address goes in brackets and matches the bare form.

```toml
allow = [
  "https://api.github.com",
  "https://*.githubusercontent.com",
  "http://127.0.0.1:8000",
  "tcp://10.0.0.8:5432",
]
```

hodor intercepts only a connection whose host and port match some allow entry. A `tcp://host:443` entry alone does not cause TLS termination, because only an `https://` entry makes the host TLS-eligible. Request matching needs the scheme, port, and host to agree. The pre-TLS interception check ignores the scheme and looks at the host and port.

## Decoy patterns

`hodor fake <ENV>` prints a decoy that is deterministic for the env name, so it stays stable across restarts. hodor picks the pattern in this order: an explicit `pattern`, a `[names.<ENV>]` registry entry, a `[providers.*]` entry that claims the env name, a `contains` match, then `{hex:32}`. That order holds within one registry file; across files a later load's pattern overrides an earlier one, regardless of tier, because the bundled table loads first and then `rules.d` in filename order.

The `contains` tier matches a substring of the lowercased env name. It selects a decoy pattern only and never grants hosts, so a name like `ACME_ANTHROPIC_KEY` gets an Anthropic-shaped decoy without reaching Anthropic. `contains` is the one exception to later-wins: matches are tried in load order, so the earliest-loaded file wins, and within one file the first provider name in sort order wins. A bundled `contains` entry therefore beats a `rules.d` entry under a different provider name, and a same-name `rules.d` provider entry loses too unless it sets `replace = true`, which discards that provider's earlier `contains` needles. The bundled entries live in `rules/registry.toml`.

```sh
hodor fake DEMO_TOKEN
# fd0c437df7ae3abca3e37d89840b4503

hodor fake GH_TOKEN
# ghp_27ac12868ee51ad4e09a0a53b61ac927d0319142

hodor fake ANTHROPIC_API_KEY
# sk-ant-api03-JtOeeFZ3iFDI4fYj0lRvy23a5CgePRG73b2hVv7Wx8451W2qaoehoSOkdM9LaqoD
```

Use `--pattern` to override the registry. The pattern verbs are `{hex:N}`, `{d:N}`, and `{base62:N}`, where N is greater than zero. Literal text passes through, so a pattern can carry any prefix. hodor rejects any other verb at startup.

```sh
hodor fake GH_TOKEN --pattern 'acme_{base62:24}'
# acme_yEXyMj1JqiTfFyxNXaoXx6n2
```

## Transparent capture

`hodor serve --tproxy` captures egress from its network namespace with kernel TPROXY: an `IP_TRANSPARENT` listener plus nftables rules and policy routes hodor installs itself over netlink (no `nft`/`ip` binaries needed). The client needs no proxy setting. Capture needs root and the `CAP_NET_ADMIN` capability. It captures LAN traffic as well as traffic to the internet. DNS and other UDP pass through unintercepted; hodor drops QUIC on port 443 via nft rule.

A raw TCP connection has no SNI, so the destination address is the identity. A `tcp://` entry must name that address.

```toml
allow = ["tcp://10.202.0.20:9000"]
```

`--tproxy` and `HODOR_TPROXY` are CLI and environment only. hodor does not read them from a config file, because TPROXY changes host nft rules and routes.

[integration/README.md](integration/README.md) has a runnable demo. It runs the container image, a client, and an upstream, and it asserts four substitution scenarios and one splice scenario.

[examples/agentic-devenv](examples/agentic-devenv/README.md) wires hodor into an agent container as its only egress service, with the real secret values in a config file the agent never reads.

## Limits

- hodor matches the request authority, not the path. A grant to `https://api.example.com` also permits `https://api.example.com/admin`.
- A `*` host allow entry matches any destination. hodor warns at startup, but the exposure is yours to accept.
- hodor swaps the decoy where it appears verbatim. A workload that hashes, signs, or re-encodes the credential before sending it sends a decoy-derived value, and the upstream rejects the request.
- A client must trust hodor's CA to reach a granted HTTPS host. Without trust, the TLS handshake fails.
- Transparent capture needs root and `CAP_NET_ADMIN` (Linux only).

## Contributing

Read [AGENTS.md](AGENTS.md) before you change the code.

License: Apache-2.0.
