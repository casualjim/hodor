# Configuration reference

Every configuration layer, file, and key. Values merge across layers; a higher layer wins.

## Layers

1. CLI flags: `--listen`, `--ca-file`, `--config`.
2. Environment variables: `HODOR_LISTEN`, `HODOR_CA_FILE`, `HODOR_CONFIG`, `HODOR_PROXY_BACKEND`, `HODOR_TPROXY_ALLOW_ROOT_NETNS`.
3. The project file at `<workspace root>/.config/hodor.toml`. The workspace root is found by walking up from the working directory.
4. The global file at `$HODOR_CONFIG` or `<config-dir>/hodor/config.toml`.

`--config <FILE>` replaces the project layer, it does not add a fifth one.

`[rules]` merges by label: a project `[rules.demo]` replaces a global `[rules.demo]` wholesale. Other sections merge per key.

## `[proxy]`

| Key | Default | Environment | Purpose |
| --- | --- | --- | --- |
| `listen` | `127.0.0.1:8080` | `HODOR_LISTEN` | Address the explicit proxy listens on. |
| `ca_file` | `<config-dir>/hodor/ca.pem` | `HODOR_CA_FILE` | Path to the CA file, which holds the certificate followed by the key. `hodor ca` also writes `ca.crt` and `ca.key` beside it. |

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

## `[workspace]`

Controls the compose stack `hodor init` generates.

| Key | Default | Purpose |
| --- | --- | --- |
| `home` | none | `$HOME` inside the agent container. Required for stack generation. Host paths under the host home translate into this prefix; other paths mount at their own path. |
| `name` | workspace path slug | Compose project name. |
| `shell` | `sh` | Shell `hodor agent` runs in the container when no command is given. |
| `include` | empty | Extra host paths the agent service mounts, translated into the container home. `~` expands; relative paths resolve against the workspace root; a trailing `:ro`/`:rw` sets the mode. Overlapping paths reuse the covering mount. A path that does not exist fails generation, because docker would mount an empty directory in its place. |

## `[agents.<name>]`

Agent config mounts for the confine stack. Every directory under `<config-dir>/hodor/agents/` whose name the table covers mounts into the agent container at the location that agent reads its own configuration from by default, so nothing has to set a config-directory variable.

| Key | Required | Purpose |
| --- | --- | --- |
| `config_dir` | yes | Container path the directory mounts at. `{home}` expands to `[workspace] home`. Must expand to an absolute path. |

```toml
[agents.trae]
config_dir = "{home}/.trae"
```

An entry overrides a built-in path for that name or adds a name the table does not carry. The mount is writable: what the agent writes lands under `<config-dir>/hodor/agents/<name>` on the host.

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
