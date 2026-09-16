# Confined agent workspace

This is a workspace you can confine. `.config/hodor.toml` is the whole input, and `hodor confine init` turns it into a two-service docker compose stack: hodor, and the agent.

The agent container holds decoy credentials and shares hodor's network namespace, so every connection it makes is captured, with no proxy setting to find and no way around the proxy. hodor swaps a decoy for the real value only on the hosts your rules allow, and puts the decoy back on the response.

## What the two services do

| Service | Job |
| --- | --- |
| `hodor` | Captures egress with TPROXY, terminates TLS on a grant match, swaps decoys for real values, redacts them back on the response. Holds the CA, and resolves real values from fnox itself. |
| `agent` | Runs the agent behind an entrypoint that trusts hodor's CA, which is all it takes to make a confined agent work. Holds decoys only. |

## Topology

```text
  agent            shares hodor's network namespace, no proxy setting
    |
    |  every connection, captured by TPROXY in the shared namespace
    v
  hodor            grant match: terminate TLS, swap the decoy for the real value
    |
    +--> api.anthropic.com   grant matched, the real key goes on the wire
    +--> anything else       spliced byte for byte, the decoy stays on the wire
```

## Before you start

- docker with compose, and hodor on `PATH`.
- The secrets this workspace uses, declared to fnox under the names in `.config/hodor.toml`.
- Your fnox setup readable by the hodor container: the stack mounts your fnox config directory and hodor's fnox files read-only, and forwards the provider credentials in your environment, so a value that resolves here resolves there.

## Run it

From this directory:

```sh
hodor rules            # fnox declarations ∩ registry, as [rules.*] blocks
hodor confine init     # write the stack, the CA, and the entrypoint
hodor confine up       # start both services
hodor confine shell    # a shell in the agent, at the workspace path
hodor confine down     # stop both
```

`init` writes three things, and never overwrites one that already exists:

| Path | What it is |
| --- | --- |
| `<state-dir>/hodor/ws/<slug>/compose.yml` | the generated stack, which is yours to edit (`<state-dir>` is `~/.local/state` on Linux) |
| `~/.config/hodor/ca.pem` | hodor's CA, with `ca.crt` and `ca.key` written beside it |
| `~/.config/hodor/proxy-entrypoint.sh` | the agent's entrypoint |

`up` merges three compose layers, later winning: `<config-dir>/hodor/compose.yml`, the generated file above, then this workspace's `.config/hodor.compose.yaml` if you create one.

## Where the secrets live

The real values stay in fnox; the hodor service resolves them itself when a request matches a grant. The agent gets one deterministic decoy per rule, shaped by that rule's pattern:

```sh
hodor fake ANTHROPIC_API_KEY    # what the agent sends
hodor fake GH_TOKEN
```

A decoy follows the env name, so renaming a variable changes its decoy and substitution stops matching until you regenerate. A rule whose key fnox does not declare produces no decoy at all.

## Check that it works

```sh
hodor confine shell
curl -sS https://api.anthropic.com/v1/models -H "x-api-key: $ANTHROPIC_API_KEY"
```

No proxy variable is set anywhere: the connection is captured on its way out. `api.anthropic.com` is a grant, so hodor terminates TLS with its own CA and the upstream sees your real key rather than the decoy.

To watch the swap, set `RUST_LOG: debug` on the hodor service in the generated compose file and read its log. The matching lines name the label and the location, never a value:

```sh
docker compose -f ~/.local/state/hodor/ws/<slug>/compose.yml logs hodor | grep substituted
```

```text
substituted label=anthropic location=Header
```

## Notes

- Capture covers every destination in the namespace, LAN included. A connection with no matching grant is spliced byte for byte, so nothing on your network breaks.
- UDP is passed through. DNS goes to the system resolver, and QUIC on port 443 is dropped, so clients fall back to TCP.
- The listener is on loopback in the shared namespace, so `HTTPS_PROXY=http://127.0.0.1:8080` works as a fallback if you would rather not rely on capture. Both paths can be live at once.
- Keep your own mounts, devices, and environment on the `agent` service: the generated file is a normal compose file for you to edit. `HODOR_IMAGE` and `AGENT_IMAGE` override the two images.
- Every directory under `~/.config/hodor/agents/` mounts into the agent at that agent's default config location, writable.
- Recreate the two services together. The agent shares hodor's network namespace, so recreating hodor alone leaves it attached to a dead namespace and its DNS stops resolving.

[How to confine a workspace](../../docs/user/how-to/confine-a-workspace.md) covers the whole flow, and the [main README](../../README.md) covers allow entries, decoy patterns, and the rest of the configuration.
