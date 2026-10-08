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
| `ca_file` | `/certs/ca.pem` when mounted there, else `<config-dir>/hodor/ca.pem` | `HODOR_CA_FILE` | Path to the CA file, which holds the certificate followed by the key. `hodor ca` also writes `ca.crt` and `ca.key` beside it. |
| `root_certs` | `[]` | — | Extra upstream CA bundles trusted on egress, additive to webpki roots. Config file only, one path per bundle. Entries extend this further with their own `root_cert`. |
| `handshake_timeout_secs` | `10` | — | Seconds the pre-auth or handshake reads may wait on a peer before the connection closes: the TLS `ClientHello`, the HTTP head, the Postgres greeting, and the upstream `SSLRequest` answer all share this budget. |

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

### Database rules

A rule whose `value` states a `postgres://` connection string is a database rule. The rule states the FAKE connection string in `value` (a proper URL, so the env var holds a URL the client can dial through hodor), and the REAL one resolves from the secret source under `env`/`fnox_key` into `real` — never stated in config. No `allow` entries: the connection string is the grant.

The connection strings carry the upstream TLS policy as libpq parameters: `sslmode` (`disable`, `allow`, `prefer`, `require`, `verify-ca`, `verify-full`; default `prefer`), `sslnegotiation` (`postgres`, default, or `direct`), `sslrootcert` (upstream trust anchor, required for a verifying sslmode), and `sslcert`/`sslkey` (upstream client identity). These parameters belong on database connection strings only; endpoint rules state the same capabilities through `[rules.<label>.tls]`.

```toml
[rules.db]
env = "DATABASE_URL"
value = "postgres://app:decoy@db.internal:5432/app"
```

## `[rules.<label>.tls."<entry>"]`

Per-entry TLS, keyed by the exact `allow` entry string. All keys optional.

| Key | Purpose |
| --- | --- |
| `client_cert` / `client_key` | Upstream client identity the proxy presents to this entry. Come together. |
| `root_cert` | Upstream CA bundle trusting this entry's host, additive to webpki roots plus global `root_certs`. |
| `guest_tls_mode` | `tls` (default) or `mtls`: demand a guest client certificate signed by the hodor CA. |
| `guest_cert` / `guest_key` | Container-internal path the guest's minted certificate and key mount at. Defaults are under the workspace state directory; set these when the client reads its pair from a fixed location. |

## `[workspace]`

Controls the compose stack `hodor init` generates.

| Key | Default | Purpose |
| --- | --- | --- |
| `home` | `/home/eng` | `$HOME` inside the agent container. Host paths under the host home translate into this prefix; other paths mount at their own path. |
| `name` | workspace path slug | Compose project name. |
| `shell` | `sh` | Shell `hodor agent` runs in the container when no command is given. |
| `init` | none | Init script inside the agent image that the generated entrypoint chains to after installing the CA (`HODOR_INIT`). The common entrypoint script names are tried when unset; the command runs directly otherwise. |
| `include` | empty | Extra host paths the agent service mounts, translated into the container home. `~` expands; relative paths resolve against the workspace root; a trailing `:ro`/`:rw` sets the mode. Overlapping paths reuse the covering mount. A path that does not exist fails generation, because docker would mount an empty directory in its place. |
| `ports` | empty | Ports published on the host as stable `127.0.0.1:<port>` bindings, forwarded to the same port inside the agent's shared network namespace. The generated stack's `fwd` sidecar exposes every agent-owned loopback listener there; a published port names one reliably from the host instead of through a changing container IP. Applying a change needs a stack restart. Port `0` and the capture listener ports (`15000`, `15001`) are refused at load. |
| `passthrough` | empty | Env names forwarded into the agent environment as `${NAME}` compose interpolation: compose substitutes the host value when the stack starts, so the generated file holds no secret and values stay fresh without regeneration. |
| `profile` | `__shared__` | Isolated tool-config namespace the generated stack mounts. Profiles inherit off `__shared__` through `profile.toml` cookies naming a parent. |

## Profiles

Isolated tool-config namespaces for the secure stack. Global profiles live under `<config-dir>/hodor/profiles/<name>/`; project ones under `<workspace root>/.config/hodor/profiles/<name>/`. Each `<tool>/` directory inside a profile mounts into the agent container at the location that tool reads its own configuration from by default, so nothing has to set a config-directory variable. The workspace selects its profile with `[workspace] profile`; unset selects `__shared__`, the base every other profile inherits off and hodor always creates.

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

## Automatic sources

`hodor agent` derives a working, decoy-only development environment from the authentication sources a workspace already carries — no declaration, the same way fnox's own chain is read. Each source present on the host maps onto grants plus a decoy twin mounted at the tool's default path; an absent source derives nothing, and the pass is liberal: a source that does not map — an ssh config whose blocks carry `Include`/`Match`/`ProxyJump` or a second identity, a broken kubeconfig — is skipped with a warning, never a failure. Only a credential-shaped gitconfig value (an `Authorization` extra header, an insteadOf base with userinfo) skips its whole source, because mounting a twin would carry a real secret.

| Source | Resolution | Twin mounts at |
| --- | --- | --- |
| gitconfig | The chain `git` itself resolves from the workspace root: globals with their `include.path`/`includeIf` follows, the repository's own config (linked worktrees resolve to the common dir), and `GIT_CONFIG_*` environment overrides. | `{home}/.gitconfig` |
| jj config | jj's user chain: `JJ_CONFIG` (a file, a `*.toml` directory, or a path list; even empty it replaces the defaults), else `~/.jjconfig.toml`, then `<config-dir>/jj/config.toml` and `<config-dir>/jj/conf.d/*.toml` in name order. `user.name`/`user.email` fall back to the resolved git chain, as jj itself falls back. | `{home}/.config/jj/config.toml` |
| ssh config | `~/.ssh/config`, per exact-host `Host` block carrying exactly one `IdentityFile`. | `{home}/.ssh/config` plus the decoy key at the mirrored path and a fresh `known_hosts` |
| kubeconfig | `KUBECONFIG` when it names a single file, else `~/.kube/config`. A file-reference kubeconfig must be flattened first: `kubectl config view --flatten --minify`. | `{home}/.kube/config` |
| talosconfig | `TALOSCONFIG` when it names a single file, else `~/.talos/config`. | `{home}/.talos/config` |

The gitconfig is a per-forge-host authentication map, never a secret store: an `Authorization` extra header or an insteadOf base with embedded userinfo fails closed, because the agent's copy must carry decoys only. For each https remote (rewritten through `url.<base>.insteadOf`) and `credential.<url>` scope whose host a fnox-declared registry name covers, the twin mints an `http.<url>.extraHeader` holding basic auth over that name's decoy — the agent runs no credential helpers, and the proxy decodes, swaps decoy for the real value, and re-encodes. Remotes over git+ssh with a `core.sshCommand -i` identity mint the same per-host ssh grant the ssh config source mints; ssh remotes without one warn. A kubeconfig source is adapted rather than byte-swapped: the API server URL becomes an `https://` allow entry, the client certificate and key materialize into a per-entry TLS identity, the cluster CA becomes that entry's `root_cert`, and the decoy twin points at the same server but carries the hodor CA plus a minted guest pair. A talosconfig adapts the same way (bare endpoints gain the Talos API port 50000); Omni `auth:` blocks carry no substitutable pair and fail closed.

## `[[workspace.file_rewrite]]`

Host files rewritten with decoys and mounted read-only into the agent — the escape hatch for files outside the automatic sources above. Each listed env name's real value is byte-replaced by its decoy in the file, and the rewritten copy lands under the workspace state directory — the agent sees decoys only; hodor holds the real values.

| Key | Required | Purpose |
| --- | --- | --- |
| `source` | yes | Host file to read. `~` and `$VAR` expand; relative paths resolve against the workspace root. |
| `dest` | yes | Container path the rewritten file mounts at, read-only. `{home}` expands to `[workspace] home` and `$VAR` expands first. |
| `envs` | no | Env names whose real values are replaced by their decoys in the file. Empty for the structural formats — `kubeconfig` (kubectl), `talos` (talosctl): the adapter knows where the secrets live. |
| `format` | no | Declared format, skipping detection. Known: `format = "kubeconfig"` and `format = "talos"`, each failing closed when the file does not parse as one. Absent, both are detected by content and other files keep the raw byte-swap. A source matching an automatic location stays with its declaration; the automatic pass skips it. |

```toml
[[workspace.file_rewrite]]
source = "~/.kube/other-cluster.yaml"
dest = "{home}/.kube/other-config"
format = "kubeconfig"
```

```toml
[[workspace.file_rewrite]]
source = ".npmrc"
dest = "{home}/.npmrc"
envs = ["NPM_TOKEN"]
```

## `[plugins.<name>]`

WASM rewrite plugins, loaded at startup; load failures fail closed. Plugins match on scheme, host and port like rule grants.

| Key | Required | Purpose |
| --- | --- | --- |
| `path` | yes | Filesystem path to the component (`.wasm`). |
| `allow` | no | Raw `scheme://host[:port]` allow entries scoping where the plugin runs. |
| `direction` | no | `both` (default), `request`, or `response`. |

```toml
[plugins.marker-request]
path = "target/plugins/marker_request.wasm"
allow = ["https://api.github.com"]
direction = "request"
```

## `[tools.<name>]`

Tool config mounts for the secure stack, by tool name.

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
