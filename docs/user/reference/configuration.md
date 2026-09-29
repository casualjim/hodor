# Configuration reference

Every configuration layer, file, and key. Values merge across layers; a higher layer wins.

## Layers

1. CLI flags: `--listen`, `--ca-file`, `--config`.
2. Environment variables: `HODOR_LISTEN`, `HODOR_CA_FILE`, `HODOR_CONFIG`, `HODOR_PROXY_BACKEND`, `HODOR_TPROXY_ALLOW_ROOT_NETNS`.
3. The project file at `<workspace root>/.config/hodor/config.toml` (legacy `.config/hodor.toml` still reads). The workspace root is found by walking up from the working directory.
4. The global file at `$HODOR_CONFIG` or `<config-dir>/hodor/config.toml`.

`--config <FILE>` replaces the project layer, it does not add a fifth one.

`[rules]` merges by label: a project `[rules.demo]` replaces a global `[rules.demo]` wholesale. Other sections merge per key.

## `[proxy]`

| Key | Default | Environment | Purpose |
| --- | --- | --- | --- |
| `listen` | `127.0.0.1:8080` | `HODOR_LISTEN` | Address the explicit proxy listens on. |
| `ca_file` | `<config-dir>/hodor/ca.pem` | `HODOR_CA_FILE` | Path to the CA file, which holds the certificate followed by the key. `hodor ca` also writes `ca.crt` and `ca.key` beside it. |
| `root_certs` | `[]` | — | Extra upstream CA bundles trusted on egress, additive to webpki roots. Config file only, one path per bundle. Entries extend this further with their own `root_cert`. |

## `[rules.<label>]`

A rule wires an environment name to the hosts it may reach, the decoy shape the client sees, and where the real value comes from. `[rules.<label>]` replaces the older `[secrets.<label>]` table; a leftover `[secrets]` table is ignored silently.

| Key | Required | Purpose |
| --- | --- | --- |
| `env` | yes | Environment variable name. Seeds the decoy, keys the registry lookup, and defaults the fnox key. |
| `value` | no | Inline real secret value. Wins over fnox. Never serialized. |
| `fnox_key` | no | fnox secret name. Defaults to `env`. |
| `allow` | no | List of `scheme://host[:port]` allow entries. Unions with the hosts the registry supplies. See [allow entries](allow-entries.md) for the grammar and host forms. |
| `pattern` | no | Decoy pattern, overriding the registry. |
| `oauth2` | no | An OAuth2 flow block overriding the registry's: declares a token issuer whose freshly issued tokens get minted as decoys. See [the registry reference](registry.md). |
| `registry` | no | Whether this rule uses registry hosts. Default `true`; `false` keeps only `allow`. |
| `if_missing` | no | `error` (default), `warn`, or `ignore`. Governs a value or hosts the rule cannot resolve. |

`env = "GITHUB_TOKEN"` alone is a complete rule when the registry knows the name: registry supplies hosts and shape, fnox supplies the value.

The registry knows public API hosts, so services it cannot bundle need explicit `allow` entries. A self-hosted or internal TLS host:

```toml
[rules.internal-api]
env = "INTERNAL_API_TOKEN"
pattern = "internal_{hex:32}"
allow = ["https://api.internal.corp"]
```

A raw TCP service such as Postgres. There is no SNI on a raw TCP connection, so the entry names the literal dialled address and port; substitution is equal-length byte swap only:

```toml
[rules.db]
env = "PGPASSWORD"
allow = ["tcp://10.0.0.8:5432"]
```

A `tcp://` entry has no framing to rewrite, so the substitution is equal-length only, and hodor satisfies that by construction: the decoy for a rule with a `tcp://` entry is generated at the real value's length, falling back from the registry shape only when the shape renders another length. See [capture traffic transparently](../how-to/capture-traffic-transparently.md) for the capture side.

## `[rules.<label>.tls."<entry>"]`

Per-entry TLS, keyed by the exact `allow` entry string. All keys optional.

| Key | Purpose |
| --- | --- |
| `client_cert` / `client_key` | Upstream client identity the proxy presents to this entry. Come together. |
| `root_cert` | Upstream CA bundle trusting this entry's host, additive to webpki roots plus global `root_certs`. |
| `guest_tls_mode` | `tls` (default) or `mtls`: demand a guest client certificate signed by the hodor CA. |

## `[workspace]`

Controls the compose stack `hodor init` generates.

| Key | Default | Purpose |
| --- | --- | --- |
| `home` | none | `$HOME` inside the agent container. Required for stack generation. Host paths under the host home translate into this prefix; other paths mount at their own path. |
| `name` | workspace path slug | Compose project name. |
| `shell` | `sh` | Shell `hodor agent` runs in the container when no command is given. |
| `include` | empty | Extra host paths the agent service mounts, translated into the container home. `~` expands; relative paths resolve against the workspace root; a trailing `:ro`/`:rw` sets the mode. Overlapping paths reuse the covering mount. A path that does not exist fails generation, because docker would mount an empty directory in its place. |
| `ports` | empty | Ports published on the host as stable `127.0.0.1:<port>` bindings, forwarded to the same port inside the agent's shared network namespace. The generated stack's `fwd` sidecar exposes every agent-owned loopback listener there; a published port names one reliably from the host instead of through a changing container IP. Applying a change needs a stack restart. Port `0` and the capture listener ports (`15000`, `15001`) are refused at load. |
| `profile` | `__shared__` | Isolated tool-config namespace the generated stack mounts. Profiles inherit off `__shared__` through `profile.toml` cookies naming a parent. |

## Profiles

Isolated tool-config namespaces for the confine stack. Global profiles live under `<config-dir>/hodor/profiles/<name>/`; project ones under `<workspace root>/.config/hodor/profiles/<name>/`. Each `<tool>/` directory inside a profile mounts into the agent container at the location that tool reads its own configuration from by default, so nothing has to set a config-directory variable. The workspace selects its profile with `[workspace] profile`; unset selects `__shared__`, the base every other profile inherits off and hodor always creates.

```toml
[workspace]
profile = "work"
```

```toml
# profiles/work/profile.toml
[profile]
parent = "__shared__"
```

A profile mounts its own tool dirs plus every tool its cookie parent names that it does not override. The mounts are writable: what the tool writes lands beside the profile on the host. No cookie means `__shared__` directly, and when both layers hold a `profile.toml` the project one wins outright. Cycles, unknown parents, and non-segment names fail generation.

## `[tools.<name>]`

Tool config mounts for the confine stack, by tool name.

| Key | Required | Purpose |
| --- | --- | --- |
| `config_dir` | yes | Container path the directory mounts at. `{home}` expands to `[workspace] home`. Must expand to an absolute path. |

```toml
[tools.trae]
config_dir = "{home}/.trae"
```

An entry overrides a built-in path for that name or adds a name the table does not carry; a named tool found nowhere is created under the selected profile. The built-in table covers the agent CLIs plus `gh` at `{home}/.config/gh`.

## Environment variables

| Variable | Effect |
| --- | --- |
| `HODOR_LISTEN` | Sets `[proxy] listen`. |
| `HODOR_CA_FILE` | Sets `[proxy] ca_file`. |
| `HODOR_CONFIG` | Sets the global config file path. |
| `HODOR_PROXY_BACKEND` | Same as `--proxy-backend`. CLI and environment only. |
| `HODOR_TPROXY_ALLOW_ROOT_NETNS` | Same as `--tproxy-allow-root-netns`. |
| `HODOR_EBPF_CGROUP` | Same as `--ebpf-cgroup`. CLI and environment only. |

## Validation

Startup rejects:

- two rules that share an env name,
- an empty `env` or `value`,
- a malformed allow entry,
- a malformed pattern.

A `*` host in an allow entry logs a warning that the grant matches any host and the secret is at risk of exfiltration.
