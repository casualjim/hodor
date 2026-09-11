# Agentic devenv with hodor

One hodor container gives an agent container fake credentials, TLS interception, and transparent capture. The agent needs no proxy setting and holds no real secret.

## What the two services do

| Service | Job |
| --- | --- |
| `hodor` | Terminates TLS on a grant match, swaps decoys for real values, and captures egress with TUN. |
| `agent` | Runs the agent. It shares hodor's network namespace and holds only decoys. |

## Topology

```text
  agent            shares hodor's network namespace, no proxy setting
    |
    |  every connection, captured by TUN policy routing
    v
  hodor            terminates TLS on a grant match and swaps the decoy
    |
    +--> api.anthropic.com   grant matched, real key on the wire
    +--> anything else       spliced byte for byte, decoy untouched
```

## Run it

The two images come from the registry, so nothing compiles locally. Both are private, so run `docker login ghcr.io` first if you have not.

Create your config from the template, then put the real values in it.

```sh
cp examples/agentic-devenv/hodor.toml.example examples/agentic-devenv/hodor.toml
$EDITOR examples/agentic-devenv/hodor.toml
```

Generate the CA. One `hodor ca` run writes the certificate and the private key to `ca.pem`, and prints the certificate alone to stdout.

```sh
mkdir -p examples/agentic-devenv/certs
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/examples/agentic-devenv/certs:/certs" \
  -e HODOR_CA_FILE=/certs/ca.pem \
  ghcr.io/casualjim/hodor:main ca > examples/agentic-devenv/certs/ca.crt
```

Start it.

```sh
docker compose -f examples/agentic-devenv/compose.yaml up -d
```

## Where the secrets live

`hodor.toml` holds the real values and is mounted into the hodor container only. It is gitignored.

The agent container holds decoys. A decoy is deterministic for its env name, so it is safe to commit, and it is the value the agent sends.

```sh
docker run --rm ghcr.io/casualjim/hodor:main fake ANTHROPIC_API_KEY
docker run --rm ghcr.io/casualjim/hodor:main fake GH_TOKEN
```

The decoy follows the env name, so renaming an env var changes its decoy. Regenerate the values in the `agent` service when you rename one, or substitution stops matching.

A decoy is shaped like a real key, which is why tools accept it, so a secret scanner can flag it. GitHub push protection allowed the two decoys in this example. A pattern that mimics a provider's live key format is more likely to be blocked.

## How the CA reaches the agent

One `hodor ca` run writes both files into `examples/agentic-devenv/certs`. hodor mounts `ca.pem`, the certificate and the private key. The agent mounts `ca.crt`, the certificate alone. An agent holding the key could mint its own leaf certificates and intercept its own traffic.

The agent reads the certificate through the variables the common toolchains use, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, and `GIT_SSL_CAINFO`. If your image installs a system trust store instead, mount the certificate there and drop those variables.

## Restart and reset

Recreate hodor and the agent together with `docker compose -f examples/agentic-devenv/compose.yaml up -d`. The agent shares hodor's network namespace, so recreating the hodor service alone leaves the agent attached to a dead namespace and its DNS stops resolving.

The CA is a file on your machine, so it survives `up` and `down`, and a certificate you install elsewhere keeps working. To rotate it, delete `examples/agentic-devenv/certs`, run `hodor ca` again, and recreate both services.

## Check that it works

Run a request inside the agent container. It has no proxy setting, so the request is captured on the way out.

```sh
docker compose -f examples/agentic-devenv/compose.yaml exec agent bash -lc \
  'curl -sS https://api.anthropic.com/v1/models -H "x-api-key: $ANTHROPIC_API_KEY"'
```

The upstream answers `401` because the key in `hodor.toml` is still a placeholder. The request reaching it is the point. It proves capture, TLS termination with hodor's CA, and substitution.

To watch the swap, set `RUST_LOG: debug` on the hodor service and read its log.

```sh
docker compose -f examples/agentic-devenv/compose.yaml logs hodor | grep substituted
```

```text
substituted label=anthropic location=Header
```

The line carries the label and the location. It never carries a value.

## Notes

- Capture covers every destination in the namespace, LAN included. A connection with no matching grant is spliced byte for byte, so nothing on your network breaks.
- UDP is relayed directly. DNS goes to the system resolver and QUIC on port 443 is dropped, so clients fall back to TCP.
- Keep your own mounts, devices, and environment on the `agent` service. Only the network namespace and the credentials change.
- `HODOR_IMAGE` and `AGENT_IMAGE` override the two images. Both defaults are private. `:main` follows the branch, and a release publishes `:<version>` and `:latest`.
- The listener is on loopback in the shared namespace. If you would rather not rely on capture, set `HTTPS_PROXY=http://127.0.0.1:8080` on the agent and both paths work at once.

[The main README](../../README.md) covers allow entries, decoy patterns, and the rest of the configuration.
