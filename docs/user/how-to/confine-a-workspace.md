# How to confine a workspace

This guide shows you how to run a coding agent inside a container that holds only decoy credentials, with hodor as its only egress path. You need hodor installed, docker with compose, and a workspace directory with secrets declared to fnox.

The confinement flow has three parts: generate rules for the secrets your workspace can already reach, describe the container layout in config, then let `hodor init` generate the compose project and `hodor up` drive it.

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
| `shell` | Shell `hodor agent` runs in the container when no command is given. Defaults to `sh`. |
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
| `~/.config/hodor/agent-entrypoint.sh` | The agent's entrypoint. It installs the mounted `ca.crt` into the container's system store with `update-ca-certificates`, then chains to the image's own init: `[workspace] init` names it (`HODOR_INIT` in the generated stack — like `shell`, it lives in the workspace config), the common entrypoint script names are tried when unset, and the command runs directly otherwise. Installing the CA needs root, directly or through passwordless `sudo`; without either it prints a warning and the container's tools do not trust hodor. `init` regenerates the file whenever it differs from the generated script, so stale or edited copies cannot linger — a custom script belongs in a compose layer overriding `entrypoint:`. |

The CA is yours after that: an existing one is never overwritten, so rotating means deleting the three files and letting `init` make a fresh CA. The entrypoint is the other way around — it is generated output, regenerated whenever it differs from the script above, because a stale copy is exactly how a stack silently stops trusting hodor. See [how to trust the CA](trust-the-ca.md) for the full range of trust options. Every mount the stack adds is conditional on the host path existing, because a bind mount of a missing path makes docker create a directory in its place.

Node and Python's `requests` read their own bundle instead of the system store, so the generated stack also points `NODE_EXTRA_CA_CERTS` and `REQUESTS_CA_BUNDLE` at the system bundle the entrypoint refreshes.

## 5. Generate, start, enter, stop

```sh
hodor init             # rules config (when absent), CA, entrypoint, and the stack (--backend picks the capture backend; ebpf by default)
hodor up               # start it
hodor logs -f          # the stack's logs (--tail N, --no-log-prefix, --workspace PATH, service names as for docker compose)
hodor agent            # init, up, and the shell in one idempotent command
hodor agent --rm       # the same, stopping the stack when the shell exits
hodor down             # stop it
```

`init` writes the workspace `.config/hodor.toml` when the workspace has none, using exactly the `[rules.*]` blocks `hodor rules` prints — a stack without rules substitutes nothing, so every credential the agent holds would stay a decoy. An existing config is the user's and is never touched; when it changes after the stack was generated, `init` regenerates `<state-dir>/hodor/ws/<slug>/compose.yml` from it (the decoys are derived from the rules, so a stale stack holds decoys that can never be swapped) and says so, since that replaces hand edits. If no rule is in play at all, `init` prints a warning naming the config file. `up` and `down` run docker compose over the layer files found on disk, in this order, later files winning:

1. `<config-dir>/hodor/compose.yml`, for additions shared by every workspace.
2. The generated per-workspace `compose.yml`.
3. The workspace's own `.config/hodor.compose.yaml` (or `.yml`), for additions local to this workspace.

`hodor agent [workspace] [--rm] [-- <command>...]` execs the configured shell as your uid at the translated workspace path, after generating what is missing and starting the stack, with `<command>` in place of the shell when you pass one. It leaves the stack running when that exits, or stops it when `--rm` is set. `logs` reads the stack's logs: `-f` to follow, `--no-log-prefix` for bare lines, `--tail <N|all>` (default `all`), service names to narrow it down, and `--workspace <PATH>` when the workspace is not the current directory.

## What the generated stack does

The hodor service runs `serve --proxy-backend <backend>`, `ebpf` unless `hodor init --backend` picked another, so the agent container, which shares hodor's network namespace, has every outbound connection captured with no proxy setting and no way around the proxy. Under `ebpf` both services carry the same `cgroup_parent`, and hodor attaches with `--ebpf-cgroup enclosing` — the cgroup its own cgroup lives under, resolved from `/proc/self/cgroup`, because the daemon places that parent relative to its own cgroup root; it also carries `cgroup: host` and the `BPF`/`PERFMON` capabilities, and the agent's inner containers land in the same cgroup. Under `tun` both services need `/dev/net/tun`. It holds the CA (`HODOR_CA_FILE=/certs/ca.pem`) and resolves the real values itself: your fnox config directory is mounted read-only at `/root/.config/fnox`, hodor's own fnox files at `/root/.config/hodor`, and every provider credential — including an age-encrypted secret, decrypted with the key inside the mounted fnox config — resolves from fnox inside the container, the way `fnox exec` would. The environment that started the stack is never a credential source.

The agent service holds only decoys, one environment variable per rule, and runs behind your entrypoint. It mounts the same workspace paths plus the agent config mounts from step 3. It runs a container runtime of its own, so it carries what that needs: unconfined seccomp, systempaths and apparmor, `SYS_CHROOT`/`AUDIT_WRITE`/`NET_ADMIN`/`SETUID`/`SETGID`/`SYS_ADMIN`, and `/dev/net/tun`. Its storage is a directory under this workspace's state, made at generation time and mounted at `{home}/.local/share/containers`. `systempaths=unconfined` is a podman option — under docker, drop it from `security_opt`.

The generated file is fully baked: image names, the agent's uid, and every mount path are concrete values chosen at generation time from your config and machine, so the stack reads as the simple thing it is. Nothing in it is env-var configurable — to differ from the generated shape, use the compose layers (`~/.config/hodor/compose.yml` globally, the workspace's `.config/hodor.compose.yaml` locally), or change the config and let `init` regenerate.

## When it breaks

- `no compose layers for ...` — run `hodor init` first, or create one of the layer files.
- `[workspace] include ... does not exist` — fix or drop the entry. Docker would mount an empty directory in its place, so generation stops instead.
- `warning: could not prepare …ca.pem` — `[proxy] ca_file` points at a container path. That is fine when you mount the CA yourself in one of the compose layers instead.
- `hodor: not root and no passwordless sudo` — the entrypoint could not refresh the system store, so nothing in the agent trusts hodor. Run the agent service as root (`user: "0"` in one of your compose layers), give that user passwordless sudo, or bake the certificate into the image — see [how to trust the CA](trust-the-ca.md).
- `[workspace] home is required` — add the `home` key from step 2.
- An inner container will not start, or podman inside the agent exits with nothing on stderr — its storage directory is not writable by the uid the agent runs as. That is why generation makes `<state-dir>/hodor/ws/<slug>/containers`; if a layer points the volume at your own directory or a named volume, `chown` it to that uid once. On Ubuntu, an inner container that dies on mount or networking also needs `apparmor=unconfined` in `security_opt`, which the generated file already sets.
- A decoy does not get swapped — the decoy was generated with a different pattern than the rule's. `hodor init` derives each decoy from its rule's `pattern` for exactly this reason; if you hand-edit the compose file, regenerate decoys with `hodor fake <ENV>` after changing a pattern.
- DNS stops resolving in the agent after recreating only the hodor service — the agent shares hodor's network namespace, so recreate both: `hodor up` again.
- `grants: 0` in hodor's startup log, or a provider answering 401 while the agent holds credentials — no rule is in play, so the decoy went out as-is. `hodor init` writes the rules config when the workspace has none; otherwise add the `hodor rules` blocks to `<workspace>/.config/hodor.toml` and regenerate.
