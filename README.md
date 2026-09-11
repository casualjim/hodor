# hodor

hodor is a grant-scoped MITM proxy that swaps a workload's format-valid decoy credential for the real value only on hosts you allow.

## How it works

A workload points its HTTP proxy setting at hodor, or hodor captures its traffic with `--tun`. Either way the workload holds a decoy credential, never the real one. The decoy is format-valid, so a tool that checks the shape of a token accepts it.

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

To include transparent capture, add the `tun` feature.

```sh
cargo build --release --features tun
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

[secrets.demo]
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

## Configuration layers

hodor reads four layers. A higher layer wins.

1. CLI flags, `--listen`, `--ca-file`, and `--config`.
2. Environment variables, `HODOR_LISTEN`, `HODOR_CA_FILE`, `HODOR_CONFIG`, `HODOR_PROJECT_ROOT`, and `HODOR_TUN`.
3. The project file at `<workspace root>/.config/hodor.toml`.
4. The global file at `$HODOR_CONFIG` or `<config-dir>/hodor/config.toml`.

hodor finds the workspace root by walking up from the working directory. `HODOR_PROJECT_ROOT` sets the root directly and skips the walk. `--config <FILE>` replaces the project file.

`[secrets]` merges by label. If the project file and the global file both define `[secrets.demo]`, the project entry replaces the global entry.

## Configuration keys

`[proxy]`:

| Key | Default | Environment | Purpose |
| --- | --- | --- | --- |
| `listen` | `127.0.0.1:8080` | `HODOR_LISTEN` | Address the proxy listens on. |
| `ca_file` | `<config-dir>/hodor/ca.pem` | `HODOR_CA_FILE` | Path to the CA file, which holds the certificate followed by the key. `hodor ca` also writes `ca.crt` and `ca.key` beside it. |

`[secrets.<label>]`:

| Key | Required | Purpose |
| --- | --- | --- |
| `env` | yes | Environment variable name. The decoy is derived from it. |
| `value` | yes | The real secret value. |
| `allow` | yes | List of allow entries. |
| `pattern` | no | Decoy pattern, overriding auto-detection. |

`HODOR_*` environment variables:

| Variable | Effect |
| --- | --- |
| `HODOR_LISTEN` | Sets `[proxy] listen`. |
| `HODOR_CA_FILE` | Sets `[proxy] ca_file`. |
| `HODOR_CONFIG` | Sets the global config file path. |
| `HODOR_PROJECT_ROOT` | Sets the workspace root. |
| `HODOR_TUN` | Same as `--tun`. CLI and environment only. |

hodor validates the config at startup. It rejects two secrets that share an env name, an empty `env` or `value`, a malformed allow entry, and a malformed pattern. A `*` host in an allow entry logs a warning that the grant matches any host and the secret is at risk of exfiltration.

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

`hodor fake <ENV>` prints a decoy that is deterministic for the env name, so it stays stable across restarts. Auto-detection matches a substring of the lowercased env name. The first match wins.

| Substring | Pattern |
| --- | --- |
| `gh_` | `ghp_{hex:40}` |
| `sk-ant-` | `sk-ant-api03-{base62:64}` |
| `sk-` | `sk-{hex:48}` |
| `anthropic` | `sk-ant-api03-{base62:64}` |
| `xox` | `xoxb-{d:10}-{d:11}-{hex:24}` |
| `slack` | `xoxb-{d:10}-{d:11}-{hex:24}` |
| none of these | `{hex:32}` |

```sh
hodor fake DEMO_TOKEN
# fd0c437df7ae3abca3e37d89840b4503

hodor fake GH_TOKEN
# ghp_2641386f5e0c6b9ea7b79c738a1015a9bc3a9ae3

hodor fake ANTHROPIC_API_KEY
# sk-ant-api03-pS6w5Sc3x3SwKriEaFJ5kBrOfItZzcJDxT4bD0UzQpvsDrhBJXUcSn3PqE0nUBdd
```

Use `--pattern` to override auto-detection. The pattern verbs are `{hex:N}`, `{d:N}`, and `{base62:N}`, where N is greater than zero. Literal text passes through, so a pattern can carry any prefix. hodor rejects any other verb at startup.

```sh
hodor fake GH_TOKEN --pattern 'acme_{base62:24}'
# acme_yEXyMj1JqiTfFyxNXaoXx6n2
```

## Transparent capture

`hodor serve --tun` captures egress from its network namespace with a userspace TCP/IP stack. The client needs no proxy setting. Capture needs root, the `CAP_NET_ADMIN` capability, and `/dev/net/tun`. It captures LAN traffic as well as traffic to the internet. It relays UDP directly. DNS goes to the system resolver, and hodor drops QUIC on port 443.

A raw TCP connection has no SNI, so the destination address is the identity. A `tcp://` entry must name that address.

```toml
allow = ["tcp://10.202.0.20:9000"]
```

`--tun` and `HODOR_TUN` are CLI and environment only. hodor does not read them from a config file, because TUN changes host routes.

[integration/README.md](integration/README.md) has a runnable demo. It runs the container image, a client, and an upstream, and it asserts four substitution scenarios and one splice scenario.

[examples/agentic-devenv](examples/agentic-devenv/README.md) wires hodor into an agent container as its only egress service, with the real secret values in a config file the agent never reads.

## Limits

- hodor matches the request authority, not the path. A grant to `https://api.example.com` also permits `https://api.example.com/admin`.
- A `*` host allow entry matches any destination. hodor warns at startup, but the exposure is yours to accept.
- hodor swaps the decoy where it appears verbatim. A workload that hashes, signs, or re-encodes the credential before sending it sends a decoy-derived value, and the upstream rejects the request.
- A client must trust hodor's CA to reach a granted HTTPS host. Without trust, the TLS handshake fails.
- Transparent capture needs root, `CAP_NET_ADMIN`, and `/dev/net/tun`.

## Contributing

Read [AGENTS.md](AGENTS.md) before you change the code.

License: Apache-2.0.
