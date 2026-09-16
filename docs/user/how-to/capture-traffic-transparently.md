# How to capture traffic transparently

This guide shows you how to make hodor capture a workload's connections without the workload knowing anything about a proxy. You need hodor on Linux, root or the `CAP_NET_ADMIN` capability, and a workload whose network namespace hodor shares or controls.

Explicit-proxy mode (point `HTTPS_PROXY` at hodor) needs none of this. Reach for TPROXY when you cannot or will not configure the client, or when the client must not be able to bypass the proxy.

## 1. Start hodor with capture on

```sh
sudo hodor serve --tproxy --config hodor.toml
```

hodor installs what it needs itself, over netlink: an `IP_TRANSPARENT` listener, nftables rules, and policy routes. No `nft` or `ip` binary is required. Capture applies to every outbound TCP connection in the network namespace, LAN destinations included.

`HODOR_TPROXY=1` is the environment equivalent.

## 2. Understand the safety guard

By default hodor refuses unscoped capture rules when it runs in the host network namespace itself. The rules reroute every outbound TCP packet, and an unclean exit would leave the machine without TCP egress until the rules are cleaned up by hand.

Two accepted shapes:

- Run hodor in its own network namespace (a container with `cap_add: NET_ADMIN`), and share that namespace with the workload. This is what `hodor confine` and the integration demo do.
- Acknowledge the risk on a disposable machine with `--tproxy-allow-root-netns` or `HODOR_TPROXY_ALLOW_ROOT_NETNS=1`.

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

- DNS and other UDP pass through unintercepted.
- QUIC on port 443 is dropped by nft rule, so HTTP/3 clients fall back to TCP and get captured. QUIC to other ports passes through.
- Connections with no matching grant are spliced byte for byte. The client sees the real upstream certificate and the decoy travels untouched, so nothing on your network breaks.

## 5. Tear down

Ctrl-C is the normal stop. The capture task's teardown guards remove the nft rules and routes. If the process was killed before it could clean up, the policy routes remain; remove them or reboot. This is the failure mode the root-netns guard exists to prevent.

## Check it works

The runnable proof is the integration demo in the repository:

```sh
git clone https://github.com/casualjim/hodor
cd hodor
mise run demo
```

It runs the container image, a client sharing hodor's netns, and an upstream on an RFC1918 subnet, and it asserts four substitution scenarios and one splice scenario. See [integration/README.md](../../../integration/README.md) for the scenario table.
