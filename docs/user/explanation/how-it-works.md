# How hodor works

The machinery behind the credential swap, and why each piece is shaped the way it is. Nothing on this page is needed to run hodor; it is for the person asking what actually happens to a packet.

## The problem hodor solves

A workload needs a credential to talk to an API. The moment the workload holds the real credential, every path it has to exfiltration (a prompt-injected `curl`, a dependency that phones home, a log line, a paste) carries the real value. You cannot fix this with a secret manager, because the manager hands the real value to exactly the party you do not fully trust.

hodor inverts who holds what. The workload holds a decoy: deterministic for the env name, format-valid, and useless everywhere except the hosts you granted. The real value lives in hodor's config, resolved from fnox, and appears on the wire only to a granted authority. The workload never sees it, not even in memory.

## The life of a connection

Two capture paths feed the same machinery.

**Explicit proxy.** The client points `HTTP(S)_PROXY` at hodor's listener. Every connection arrives labelled with its destination host and port.

**Transparent capture (Linux).** `--proxy-backend` selects a backend. `tproxy` installs an `IP_TRANSPARENT` listener plus nftables rules and policy routes over netlink, so the kernel redirects every outbound TCP connection in the namespace to hodor; UDP passes through and QUIC on port 443 is dropped so HTTP/3 clients fall back to TCP. `tun` opens a TUN device and feeds it into a userspace stack (smoltcp, medium-ip, any-ip), with policy routes in a dedicated table pointing at the device, and handles UDP itself: DNS relayed to the system resolver, QUIC dropped, other flows relayed to their destination. Both are peers — same interception contract, different mechanism — and in both the client configured nothing and cannot bypass the proxy. hodor marks its own upstream dials so its egress never loops back into its own capture.

Then, per connection:

1. **Gate.** hodor parses the connection head and checks the destination against the rules' allow entries. No match means splice: both directions are pumped through byte for byte, the client sees the real upstream certificate, and the decoy travels untouched. This is the default for the internet at large, and it is why non-matching traffic keeps working.
2. **SNI.** For a matching TLS connection, hodor parses the ClientHello for the server name (a hand-rolled parser, `sni.rs`, bounded at 16 KiB) and looks up a per-domain leaf certificate in a lock-free cache. An expired leaf rotates on the next lookup.
3. **Terminate.** hodor terminates TLS with that leaf, signed by its own CA. This is why granted HTTPS hosts require client trust in the CA.
4. **Sniff.** hodor peeks at the plaintext stream to tell HTTP/1 from HTTP/2 (h2 preface) from raw bytes.
5. **Substitute.** Guest-to-server chunks pass through a request machine that swaps decoy for real; server-to-guest chunks pass through a response machine that swaps real back to decoy. The substitution engine walks HTTP/1 headers and bodies, and HTTP/2 headers via an hpack frame walker. Raw TCP (a `tcp://` grant) gets a byte-level scan-and-forward: framing uncertainty degrades to opaque scanning, never blocks.
6. **Log.** A substitution logs its rule label and the location (`Header`, `BasicAuth`, `Body`), never a value.

## Why the pieces are shaped this way

**Grant by authority, not URL.** The client dials a host:port; the grant names a host:port. Path-level authorisation would require hodor to understand every API's semantics, and a workload that re-encodes or signs the credential defeats substitution anyway. Authority-level grants keep the model honest about what is enforceable.

**Decoys are deterministic.** A decoy seeded from the env name survives restarts and is safe to commit, which is what lets a compose file carry it as a plain environment variable. The cost is that renaming an env var changes the decoy, and a stale decoy stops matching.

**Splice is byte-identical.** Non-granted traffic is not re-serialised or re-framed. Performance and correctness both depend on the non-matching path being a pipe.

**Write-once state.** `ProxyState` is built once at startup behind an `Arc`; there is no reload. Certificates live in a `DashMap` so lookups are lock-free and keygen happens on the caller's thread, never under a lock. Per-connection work is a `tokio::spawn`, with a 10-second budget on pre-auth and dial phases.

**Capture opts in at the CLI only.** Capture mutates host routes, and TPROXY also host nft rules. Reading it from a config file would make it ambient; hodor requires the explicit flag, binds its listener before touching the host, and tears the rules down on exit.

## Where the secrets live

Real values come from an inline `value` (wins) or from fnox, whose discovery chain hodor extends with one level of its own (`<config-dir>/hodor/fnox.toml`). hodor logs label and location only. Environment redactions (`*_TOKEN`, `*_SECRET`, `*_KEY`, `*_PASSWORD`) keep values out of its own environment dumps.

The CA is a file pair: certificate plus key in `ca.pem` for hodor, certificate alone in `ca.crt` for clients. Whoever holds the key can mint leaves, so `ca.key` goes nowhere.
