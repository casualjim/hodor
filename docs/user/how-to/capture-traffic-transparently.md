# How to capture traffic transparently

This guide shows you how to make hodor capture a workload's connections without the workload knowing anything about a proxy. You need hodor on Linux, root, and a workload whose network namespace hodor shares or controls.

Explicit-proxy mode (point `HTTPS_PROXY` at hodor) needs none of this. Reach for transparent capture when you cannot or will not configure the client, or when the client must not be able to bypass the proxy.

Transparent capture comes in two backends, chosen with `--proxy-backend`. `tproxy` is the kernel path: nftables rules and policy routes hand TCP to an `IP_TRANSPARENT` listener, and UDP passes through untouched except for the QUIC drop. `tun` is the userspace path: hodor opens a TUN device and runs its own TCP/IP stack, so it relays UDP itself (DNS to the system resolver, QUIC dropped), and it needs a binary built with the `tun` feature. They are peers, not a migration path — pick by mechanism, not by age.

## 1. Start hodor with a capture backend

```sh
sudo hodor serve --proxy-backend tproxy --config hodor.toml
```

Or, with a binary built `--features tun`:

```sh
sudo hodor serve --proxy-backend tun --config hodor.toml
```

Both install what they need themselves, over netlink: `tproxy` an `IP_TRANSPARENT` listener plus nftables rules and policy routes, `tun` the device plus policy routes. No `nft` or `ip` binary is required. Capture applies to every outbound TCP connection in the network namespace, LAN destinations included.

`HODOR_PROXY_BACKEND=tproxy` and `HODOR_PROXY_BACKEND=tun` are the environment equivalents.

## 2. Understand the safety guard

With `--proxy-backend tproxy`, hodor refuses unscoped capture rules when it runs in the host network namespace itself. The rules reroute every outbound TCP packet, and an unclean exit would leave the machine without TCP egress until the rules are cleaned up by hand.

Two accepted shapes:

- Run hodor in its own network namespace (a container with `cap_add: NET_ADMIN`), and share that namespace with the workload. This is what `hodor confine` and the integration demo do.
- Acknowledge the risk on a disposable machine with `--tproxy-allow-root-netns` or `HODOR_TPROXY_ALLOW_ROOT_NETNS=1`.

`tun` has no such guard: the policy routes it installs name the TUN device, and the teardown guard removes them on exit.

## 3. Grant raw TCP by destination address

A captured TLS connection is identified by SNI, so HTTPS grants work as usual:

```toml
allow = ["https://api.anthropic.com"]
```

A raw TCP connection has no SNI. The destination address is the only identity, so a `tcp://` grant must name the literal address the workload dials:

```toml
allow = ["tcp://10.202.0.20:9000"]
```

A `tcp://` entry requires an explicit port. Plain HTTP capture identifies the connection by its `Host` header, so `http://api.internal:8000` grants cleartext HTTP with no address guessing.

## 4. Know what passes through

With `--proxy-backend tproxy`:

- DNS and other UDP pass through unintercepted.
- QUIC on port 443 is dropped by nft rule, so HTTP/3 clients fall back to TCP and get captured. QUIC to other ports passes through.

With `--proxy-backend tun`, the UDP path runs inside hodor instead: DNS is relayed to the system resolver, QUIC on port 443 is dropped, and any other UDP flow is relayed to its original destination.

Either way, connections with no matching grant are spliced byte for byte. The client sees the real upstream certificate and the decoy travels untouched, so nothing on your network breaks.

## 5. Tear down

Ctrl-C is the normal stop; hodor handles SIGINT at process level, drops the capture task, and the teardown guard removes the nft rules and policy routes. If the process was killed outright before it could clean up, the policy rules remain — under `tproxy` that means no TCP egress until they are removed by hand (the failure mode the root-netns guard exists to prevent), and under `tun` a stale capture-table default route blackholes egress. Reboot or remove them.

## Check it works

The runnable proof is the integration demo in the repository:

```sh
git clone https://github.com/casualjim/hodor
cd hodor
mise run demo
```

It runs the container image, a client sharing hodor's netns, and an upstream on an RFC1918 subnet, and it asserts four substitution scenarios and one splice scenario. See [integration/README.md](../../../integration/README.md) for the scenario table.
