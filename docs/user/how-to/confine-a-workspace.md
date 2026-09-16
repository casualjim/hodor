# How to confine a workspace

This guide shows you how to run a coding agent inside a container that holds only decoy credentials, with hodor as its only egress path. You need hodor installed, docker with compose, and a workspace directory with secrets declared to fnox.

The confinement flow has three parts: generate rules for the secrets your workspace can already reach, describe the container layout in config, then let `hodor confine` generate and drive the compose project.

## 1. Generate rules from what fnox knows

From your workspace root:

```sh
hodor rules
```

This prints one `[rules.<label>]` block per env var that fnox declares and the bundled registry knows. Each block carries `env` and `if_missing = "warn"` and nothing else, because the registry already supplies the allowed hosts and the decoy shape. Names the registry knows but states no hosts for, and fnox declarations no registry entry covers, are listed in comments at the end.

Paste the output into your workspace's `.config/hodor.toml`, removing any names you do not want swapped:

```toml
[rules.github_token]
env = "GITHUB_TOKEN"
if_missing = "warn"
```

A rule with no `value` resolves its real value from fnox at serve time. See [how to get values from fnox](get-values-from-fnox.md) if a name is missing.

## 2. Describe the container layout

`[workspace]` in the same config file controls the generated stack:

```toml
[workspace]
home = "/home/eng"
shell = "zsh"
include = ["~/.config/mise:ro", "../sibling-project"]
```

| Key | Purpose |
| --- | --- |
| `home` | `$HOME` inside the agent container. Required for stack generation. Host paths under your home directory translate into this prefix; other paths mount at their own location. |
| `shell` | Shell invoked by `hodor confine shell`. Defaults to `sh`. |
| `include` | Extra host paths the agent service mounts. `~` expands; relative paths resolve against the workspace root. A trailing `:ro` or `:rw` sets the mount mode, `rw` by default. Every path must exist: generation stops rather than let docker mount an empty directory in its place. |
| `name` | Compose project name. Defaults to a slug of the workspace path. |

The workspace root itself is always mounted, at its translated path.

## 3. Mount agent configuration

Every directory under `<config-dir>/hodor/agents/<name>` mounts into the agent container at the location that agent reads its own configuration from by default. Create the directory for each agent you use:

```sh
mkdir -p ~/.config/hodor/agents/pi ~/.config/hodor/agents/opencode
```

The built-in table covers `amazon-q`, `amp`, `auggie`, `claude`, `cline`, `codebuddy`, `codebuff`, `codex`, `continue`, `copilot`, `crush`, `cursor`, `deepagents`, `droid`, `dsh`, `forge`, `gemini`, `goose`, `gptme`, `grok`, `hermes`, `iflow`, `junie`, `kilo`, `kimi`, `kimi-code`, `kiro`, `mimo-code`, `muse-code`, `omp`, `open-interpreter`, `openclaw`, `openhands`, `opencode`, `pi`, `qoder`, `qwen`, `roo`, `trae`, `vibe`, and `warp`, plus their common CLI-name spellings.

An agent the table does not carry gets its path from config:

```toml
[agents.my-agent]
config_dir = "{home}/.my-agent"
```

The mounts are writable. Whatever the agent writes lands under `<config-dir>/hodor/agents/<name>` on the host.

## 4. The entrypoint and the CA

`init` writes both files the generated stack mounts, when they are missing:

| File | What it is |
| --- | --- |
| `~/.config/hodor/ca.pem` | hodor's CA, with `ca.crt` and `ca.key` written beside it. Delete the three to rotate; `init` and `up` create them again. |
| `~/.config/hodor/proxy-entrypoint.sh` | The agent's entrypoint. It installs the mounted `ca.crt` into the container's system store with `update-ca-certificates`, then `exec`s the command. That needs root, directly or through passwordless `sudo`; without either it prints a warning and the container's tools do not trust hodor. |

Both are yours after that: nothing existing is overwritten, so edit the entrypoint freely and your version keeps running. Set `HODOR_ENTRYPOINT` to mount a different script, `HODOR_CA` and `HODOR_CA_CRT` to point at a CA somewhere else. See [how to trust the CA](trust-the-ca.md) for the full range of options. Every mount the stack adds is conditional on the host path existing, because a bind mount of a missing path makes docker create a directory in its place.

Node and Python's `requests` read their own bundle instead of the system store, so the generated stack also points `NODE_EXTRA_CA_CERTS` and `REQUESTS_CA_BUNDLE` at the system bundle the entrypoint refreshes.

## 5. Generate, start, enter, stop

```sh
hodor confine init     # generate the stack, the CA, and the entrypoint once, as editable files
hodor confine up       # start it
hodor confine shell    # shell into the agent, in the workspace directory
hodor confine down     # stop it
```

`init` writes `<state-dir>/hodor/ws/<slug>/compose.yml` only when absent, so your edits survive regeneration. `up` and `down` run docker compose over the layer files found on disk, in this order, later files winning:

1. `<config-dir>/hodor/compose.yml`, for additions shared by every workspace.
2. The generated per-workspace `compose.yml`.
3. The workspace's own `.config/hodor.compose.yaml` (or `.yml`), for additions local to this workspace.

`confine shell` execs the configured shell as your uid at the translated workspace path.

## What the generated stack does

The hodor service runs `serve --proxy-backend tproxy`, so the agent container, which shares hodor's network namespace, has every outbound connection captured with no proxy setting and no way around the proxy. It holds the CA (`HODOR_CA_FILE=/certs/ca.pem`) and resolves the real values itself: your fnox config directory is mounted read-only at `/root/.config/fnox`, hodor's own fnox files at `/root/.config/hodor`, and the provider credentials present in the environment that ran `confine up` are forwarded by name. A provider token fnox itself declares is resolved inside the container, the way `fnox exec` would.

The agent service holds only decoys, one environment variable per rule, and runs behind your entrypoint. It mounts the same workspace paths plus the agent config mounts from step 3. It runs a container runtime of its own, so it carries what that needs: unconfined seccomp, systempaths and apparmor, `SYS_CHROOT`/`AUDIT_WRITE`/`NET_ADMIN`/`SETUID`/`SETGID`/`SYS_ADMIN`, and `/dev/net/tun`. Its storage is a host directory made at generation time, mounted at `{home}/.local/share/containers`. `systempaths=unconfined` is a podman option — under docker, drop it from `security_opt`.

Two environment overrides tune the images: `HODOR_IMAGE` (default `ghcr.io/casualjim/hodor:latest`) and `AGENT_IMAGE` (default `ghcr.io/casualjim/devagent:26.04`). `HODOR_CA` and `HODOR_CA_CRT` override the CA file locations, and `HODOR_AGENT_STORAGE` overrides where the agent's inner container storage comes from (default `<config-dir>/hodor/agent-containers`).

## When it breaks

- `no compose layers for ...` — run `hodor confine init` first, or create one of the layer files.
- `[workspace] include ... does not exist` — fix or drop the entry. Docker would mount an empty directory in its place, so generation stops instead.
- `warning: could not prepare …ca.pem` — `[proxy] ca_file` points at a container path. That is fine when you mount the CA yourself: set `HODOR_CA` to the host file and `HODOR_CA_CRT` to the certificate the agent should trust.
- `hodor: not root and no passwordless sudo` — the entrypoint could not refresh the system store, so nothing in the agent trusts hodor. Run the agent service as root (`user: "0"` in one of your compose layers), give that user passwordless sudo, or bake the certificate into the image — see [how to trust the CA](trust-the-ca.md).
- `[workspace] home is required` — add the `home` key from step 2.
- An inner container will not start, or podman inside the agent exits with nothing on stderr — its storage directory is not writable by the uid the agent runs as. That is why generation makes `<config-dir>/hodor/agent-containers`; if you point `HODOR_AGENT_STORAGE` at your own directory or use a named volume, `chown` it to that uid once. On Ubuntu, an inner container that dies on mount or networking also needs `apparmor=unconfined` in `security_opt`, which the generated file already sets.
- A decoy does not get swapped — the decoy was generated with a different pattern than the rule's. `confine init` derives each decoy from its rule's `pattern` for exactly this reason; if you hand-edit the compose file, regenerate decoys with `hodor fake <ENV>` after changing a pattern.
- DNS stops resolving in the agent after recreating only the hodor service — the agent shares hodor's network namespace, so recreate both: `hodor confine up` again.
