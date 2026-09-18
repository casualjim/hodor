# The security model

What hodor defends against, what it does not, and the edges you are choosing to accept. Read this before relying on it for anything that matters.

## The property hodor buys you

A credential that leaves the workload is the decoy. The workload holds only a format-valid fake. Concretely:

- **Exfiltration to a third party.** A prompt-injected tool, a curious dependency, or a log sink receives the decoy. Any host outside the allow entries gets the decoy and rejects it. The real value never travels there.
- **Leaked environment or config.** A container dump, a screenshot, a paste of `env`: all carry decoys, which are deterministic and safe to commit.
- **The response path.** hodor redacts real values back to decoys in responses, so even output from a granted host shows the client the fake.

The grant list is the blast radius. `https://api.anthropic.com` means the real key reaches exactly that authority (any path on it, see below) and nowhere else.

## What hodor is not

- **Not a sandbox.** hodor constrains where a real credential travels on the wire. It does not constrain what the workload computes, reads, or writes. A workload that can exfiltrate data can exfiltrate everything except the real credential.
- **Not path authorisation.** Grants match the authority. A grant to `https://api.example.com` permits `/admin` as much as `/v1/models`. If an API's paths differ in sensitivity, treat the credential as granted to all of them.
- **Not protection against credential-derived payloads.** hodor swaps the decoy where it appears verbatim, in headers, basic auth, and bodies, over HTTP/1 and HTTP/2. A workload that hashes, signs, or re-encodes the credential before sending sends a decoy-derived value, and the upstream rejects the request. That rejection is the system working; it is also a workload hodor cannot help.
- **Not anonymous.** hodor terminates TLS on granted hosts, which means it reads that traffic. You are moving trust from the API's certificate to your CA, deliberately, for a scoped set of hosts.

## Edges you accept

| Edge | Consequence |
| --- | --- |
| `*` as a grant host | Matches any destination. hodor warns at startup; the exposure is yours to accept. |
| A non-loopback listen address | Anyone reaching the port triggers real-secret substitution. Warned at startup. |
| CA key distribution | Whoever holds `ca.key` or `ca.pem` can mint leaf certificates and intercept granted traffic. Distribute `ca.crt` only. |
| Compromised hodor process | It holds every real value and the CA. It runs as root with capture enabled, and with `CAP_NET_ADMIN` under TPROXY. Treat the hodor container as tier-zero; keep its mounts minimal. |
| Workload trusts extra CAs | A workload with its own MITM proxy in front of hodor sees pre-substitution traffic only if it holds the real credential, which it does not; but it can still see decoy traffic and everything else in the namespace. |
| QUIC to non-443 ports | Passes through unintercepted. Only `:443` QUIC is dropped. |

With `--proxy-backend tun`, UDP is not a pass-through: DNS is relayed to the system resolver and other non-443 UDP flows are relayed to their original destination from inside hodor, so the workload's UDP leaves from hodor's sockets.

With `--proxy-backend ebpf`, connected UDP is relayed unchanged (no substitution), and unconnected `sendto` traffic such as typical DNS is not captured at all. Capture is scoped by cgroup membership rather than by network namespace, so a process that escapes the cgroup leaves the capture; hodor must be run outside that cgroup, which the PID check enforces a second time. The capability set is `CAP_BPF` + `CAP_NET_ADMIN` rather than the wider privileges `tun` needs.

## Fail-closed defaults

The design prefers refusal over degradation:

- A fnox-declared key that cannot resolve fails startup, whatever `if_missing` says. Only an undeclared key honours `warn`/`ignore`.
- A capture leg that dies ends the process rather than silently serving explicit-proxy only.
- Malformed traffic closes the connection quietly; framing uncertainty degrades to opaque byte forwarding, never to skipping substitution.
- Two rules sharing an env name, an empty value, a malformed grant or pattern: startup refuses.

## Residual trust

You still trust, in order: the hodor binary and its config path (anyone who edits the config can add a grant), the host running it, and the CA file's location. hodor shrinks the trusted surface from "every process in the workload" to "one process whose only job is not to leak".
