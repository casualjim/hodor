# CLI reference

Every subcommand, flag, and environment variable, as the binary accepts them. `serve` is the default when no subcommand is given.

## Global flags

| Flag | Environment | Meaning |
| --- | --- | --- |
| `--config <FILE>` | `HODOR_CONFIG` | Config file replacing the project layer. |

## `hodor serve`

Serve the proxy.

| Flag | Environment | Meaning |
| --- | --- | --- |
| `--listen <ADDR>` | `HODOR_LISTEN` | Explicit-proxy listen address. Default `127.0.0.1:8080`. |
| `--ca-file <PATH>` | `HODOR_CA_FILE` | CA PEM path (certificate followed by key). Default `<config-dir>/hodor/ca.pem`. |
| `--tproxy` | `HODOR_TPROXY` | Also capture via kernel TPROXY. Needs `CAP_NET_ADMIN`; Linux only. |
| `--tproxy-allow-root-netns` | `HODOR_TPROXY_ALLOW_ROOT_NETNS` | Allow unscoped capture rules in the host network namespace. Disposable machines only. |

`--tproxy` and `--tproxy-allow-root-netns` are CLI and environment only, deliberately absent from config files: TPROXY mutates host nft rules and routes, so enabling it is an explicit act, not ambient configuration.

The listener binds before any capture side effect, so a bad listen address fails before nft rules touch the host. With `--tproxy`, a failed TPROXY leg ends the process rather than silently serving explicit-proxy only.

## `hodor fake <ENV> [--pattern <PATTERN>]`

Print the deterministic decoy for an env var name. `--pattern` overrides the registry-supplied shape for this invocation only. See [decoy patterns](decoy-patterns.md).

## `hodor ca`

Generate or load the CA, print its certificate PEM to stdout, and write `ca.crt` and `ca.key` beside the CA file. The printed PEM is the trust anchor to install into workload containers; the private key stays in the CA file and in `ca.key`.

## `hodor rules`

Print `[rules.*]` blocks for the secrets this workspace can get: the intersection of fnox declarations and the known-host registry. Values resolve from fnox at serve time; the output carries env names only. Names the registry knows but states no hosts for are printed commented out; fnox declarations no registry entry covers are listed at the end.

## `hodor confine <ACTION> [WORKSPACE]`

Confine a workspace: generate its stack once as an editable file, then start and stop the layered docker compose project. `WORKSPACE` defaults to the current directory.

| Action | Meaning |
| --- | --- |
| `init` | Generate `<state-dir>/hodor/ws/<slug>/compose.yml` if absent. Existing files are left untouched so edits survive. |
| `up` | Start the layered compose project from the files on disk. |
| `down` | Stop the layered compose project. |
| `shell` | Exec the configured shell in the agent container at the translated workspace directory. |

See [how to confine a workspace](../how-to/confine-a-workspace.md).

## Exit behaviour

Malformed client traffic closes the connection quietly; it never fails the process. Configuration errors, CA errors, and a failed TPROXY leg fail startup or the process. Listening on a non-loopback address logs a warning: anyone reaching the port can trigger real-secret substitution.
