# Integration demo (transparent capture)

Runs the real container image (runtime-only `Dockerfile`, prebuilt
binary) in the deployment shape hodor exists for: the
client container shares hodor's network namespace and knows nothing about
any proxy. hodor runs `serve --proxy-backend tproxy` and installs its nft rules and
policy routing inside the shared netns, so every client connection is
captured on the way out.

Topology:

- `client` — `network_mode: service:hodor`; talks to `api` by plain
  hostname:port. Holds only the deterministic fake (`hodor fake GH_TOKEN`).
- `hodor` — legs on the default bridge and the `server` network;
  `cap_add: NET_ADMIN` for the TPROXY listener, nft rules, and policy
  routes (all self-installed over netlink — the runtime image ships no
  `nft`/`ip`). Marked upstream dials bypass capture (fwmark rule).
- `api` — bun server on `server` only, static IP `10.202.0.20`,
  validates only the real token.
- `server` subnet is RFC1918 on purpose: hodor captures LAN traffic too
  (the capture routes are default-route-only), and this demo proves it.

| # | Client does | Grant | Passes when |
| --- | ------------- | ------- | ------------- |
| 1 | HTTPS GET `api:8443` with the fake bearer | `https://api:8443` | server saw the real bearer, response body redacted back to the fake |
| 2 | Cleartext HTTP GET `api:8000` with the fake bearer | `http://api:8000` | same as 1 through transparent plain-HTTP capture (Host header identity) |
| 3 | Cleartext line protocol to `api:9000` | `tcp://10.202.0.20:9000` | `AUTH fake` became `AUTH real`, `OK real` came back as `OK fake` |
| 4 | TLS line protocol to `api:9443` | `https://api:9443` | same as 3 through terminated TLS legs |
| 5 | TLS line protocol to `api:9444` | none | tunnel splices untouched: fake arrives as-is, server rejects |

Scenario 3's grant host is the literal destination IP because raw TCP
capture has no SNI — the destination address is the identity
(`src/tproxy/mod.rs` `tproxy_conn_task`). Scenario 5 is the fail-closed control: without a grant
hodor splices TLS byte-identical, so no secret can leak and the server
refuses the fake.

## Run

```sh
mise run demo
```

The task builds the release binary, packs it into
the runtime image via the repo `Dockerfile`, and runs
`docker compose up --abort-on-container-exit --exit-code-from client`.
Client exit code 0 means every scenario passed.

Recomputing the fake after changing `env` in `hodor.toml`:

```sh
mise run build -- --release
target/release/hodor fake GH_TOKEN
```

Update the value in `compose.yaml` (`client.environment.HODOR_FAKE`) to match.
