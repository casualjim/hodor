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
| `include` | Extra host paths the agent service mounts. `~` expands; relative paths resolve against the workspace root. A trailing `:ro` or `:rw` sets the mount mode, `rw` by default. |
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

## 4. Provide the agent entrypoint

The generated agent service runs `~/.config/hodor/proxy-entrypoint.sh` as its entrypoint and mounts `~/.config/hodor/ca.crt` into the system CA location. The entrypoint is yours to own; its job is to make the hodor CA trusted inside the container before handing off to the command. A minimal version:

```sh
#!/bin/sh
set -e
CA_SRC=/usr/local/share/ca-certificates/hodor-ca.crt
if [ "$(id -u)" = "0" ] && command -v update-ca-certificates >/dev/null 2>&1; then
  update-ca-certificates >/dev/null 2>&1 || true
fi
BUNDLE_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/hodor"
mkdir -p "$BUNDLE_DIR" 2>/dev/null || true
if cat /etc/ssl/certs/ca-certificates.crt "$CA_SRC" >"$BUNDLE_DIR/ca-bundle.pem" 2>/dev/null; then
  export SSL_CERT_FILE="$BUNDLE_DIR/ca-bundle.pem"
  export REQUESTS_CA_BUNDLE="$BUNDLE_DIR/ca-bundle.pem"
  export NODE_EXTRA_CA_CERTS="$BUNDLE_DIR/ca-bundle.pem"
fi
exec "$@"
```

Set `HODOR_ENTRYPOINT` on `confine up` to point somewhere else. See [how to trust the CA](trust-the-ca.md) for the full range of options.

## 5. Generate, start, enter, stop

```sh
hodor confine init     # generate the stack once, as an editable file
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

The hodor service runs `serve --tproxy`, so the agent container, which shares hodor's network namespace, has every outbound connection captured with no proxy setting and no way around the proxy. It holds the CA (`HODOR_CA_FILE=/certs/ca.pem`) and mounts your fnox age identity read-only (`~/.config/fnox/age.txt`), so it can resolve real values itself.

The agent service holds only decoys, one environment variable per rule, and runs behind your entrypoint. It mounts the same workspace paths plus the agent config mounts from step 3.

Two environment overrides tune the images: `HODOR_IMAGE` (default `ghcr.io/casualjim/hodor:latest`) and `AGENT_IMAGE` (default `ghcr.io/casualjim/devenv:omp`). `HODOR_CA` and `HODOR_CA_CRT` override the CA file locations.

## When it breaks

- `no compose layers for ...` — run `hodor confine init` first, or create one of the layer files.
- `[workspace] home is required` — add the `home` key from step 2.
- A decoy does not get swapped — the decoy was generated with a different pattern than the rule's. `confine init` derives each decoy from its rule's `pattern` for exactly this reason; if you hand-edit the compose file, regenerate decoys with `hodor fake <ENV>` after changing a pattern.
- DNS stops resolving in the agent after recreating only the hodor service — the agent shares hodor's network namespace, so recreate both: `hodor confine up` again.
