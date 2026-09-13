#!/usr/bin/env bash
# Transparent-capture demo without docker: a network namespace, a veth up
# to the host, and hodor's self-installed TPROXY rules inside the netns.
# The client runs under bwrap (filesystem-sandboxed) while sharing the
# netns, so it is captured like any proxy-unaware workload.
#
# Requires: sudo (netns, veth, host nft), iproute2, nft, openssl, bun, curl, bwrap.
# Run: mise run demo:bwrap (builds as you, escalates only this script)
set -euo pipefail

proj_dir=$(cd "$(dirname "$0")/../.." && pwd)
binary=$proj_dir/target/release/hodor

NS=hodor-bwrap
HOST_IF=hb-host
NS_IF=hb-ns
API_IP=10.99.0.20
GW_IP=10.99.0.1
REAL=ghp_deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
NAT_TABLE=hodor_bwrap_nat

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run as root (sudo)"
for tool in ip nft openssl bun curl bwrap; do
  command -v "$tool" >/dev/null || fail "missing tool: $tool"
done
[ -x "$binary" ] || fail "build first: mise run build -- --release"

work=$(mktemp -d /tmp/hodor-bwrap.XXXXXX)
certs=$work/certs
mkdir -p "$certs"

api_pid=""
hodor_pid=""
cleanup() {
  [ -n "$api_pid" ] && kill "$api_pid" 2>/dev/null || true
  [ -n "$hodor_pid" ] && kill "$hodor_pid" 2>/dev/null || true
  rm -rf "$work"
  ip netns del "$NS" 2>/dev/null || true
  nft delete table inet "$NAT_TABLE" 2>/dev/null || true
}
trap cleanup EXIT

bash "$proj_dir/integration/gen-certs.sh" "$certs" >/dev/null

FAKE=$("$binary" fake GH_TOKEN)

# Netns + veth + NAT: the client namespace reaches the world only through
# the host, and hodor captures everything on the way out.
ip netns add "$NS"
mkdir -p "/etc/netns/$NS"
printf 'nameserver 1.1.1.1\n' >"/etc/netns/$NS/resolv.conf"
ip link add "$HOST_IF" type veth peer name "$NS_IF"
ip link set "$NS_IF" netns "$NS"
ip addr add "$GW_IP/24" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip netns exec "$NS" ip addr add 10.99.0.2/24 dev "$NS_IF"
ip netns exec "$NS" ip link set "$NS_IF" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip route add default via "$GW_IP"
sysctl -qw net.ipv4.ip_forward=1
nft add table inet "$NAT_TABLE"
nft "add chain inet ${NAT_TABLE} postrouting { type nat hook postrouting priority srcnat; }"
nft add rule inet "$NAT_TABLE" postrouting ip saddr 10.99.0.0/24 oifname "$HOST_IF" masquerade

cat >"$work/hodor.toml" <<EOF
[proxy]
listen = "0.0.0.0:8080"
ca_file = "$certs/ca.pem"

[rules.demo]
env = "GH_TOKEN"
value = "$REAL"
registry = false
allow = ["https://api:8443", "tcp://$API_IP:9000"]
EOF

# API server (validates only the real token) inside the namespace.
ip netns exec "$NS" env HODOR_REAL="$REAL" CERT_DIR="$certs" \
  bun run "$proj_dir/integration/api/server.ts" >"$work/api.log" 2>&1 &
api_pid=$!

# hodor with kernel TPROXY inside the same namespace.
ip netns exec "$NS" RUST_LOG=info "$binary" serve --tproxy --config "$work/hodor.toml" >"$work/hodor.log" 2>&1 &
hodor_pid=$!

# Sandbox wrapper: bwrap shares the netns (no --unshare-net) but isolates
# the filesystem; the client needs /certs for the CA and nothing else.
client() {
  ip netns exec "$NS" bwrap \
    --ro-bind /usr /usr \
    --symlink usr/bin /bin \
    --symlink usr/lib /lib \
    --symlink usr/lib64 /lib64 \
    --dev /dev \
    --tmpfs /tmp \
    --ro-bind "$certs" /certs \
    --clearenv \
    --setenv PATH /usr/bin:/bin \
    "$@"
}

wait_port() {
  for _ in $(seq 1 50); do
    if ip netns exec "$NS" bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; then
      return 0
    fi
    kill -0 "$api_pid" 2>/dev/null || fail "api server died (see $work/api.log)"
    kill -0 "$hodor_pid" 2>/dev/null || fail "hodor died (see $work/hodor.log)"
    sleep 0.2
  done
  fail "timeout waiting for $1:$2 in the namespace"
}

wait_port "$API_IP" 8443
wait_port "$API_IP" 9000

# Scenario 1: HTTPS with the fake bearer -> server sees real, response
# redacts back to the fake.
body=$(client curl -sS --max-time 10 --cacert /certs/ca.crt \
  --resolve "api:8443:$API_IP" \
  -H "Authorization: Bearer $FAKE" \
  https://api:8443/)
[ "$body" = "token:$FAKE" ] || fail "https scenario: got '$body', want 'token:$FAKE'"

# Scenario 2: raw TCP line protocol under a tcp:// grant -> AUTH fake
# becomes AUTH real upstream, OK real comes back as OK fake.
reply=$(client timeout 10 bash -c "exec 3<>/dev/tcp/$API_IP/9000; printf 'AUTH $FAKE\n' >&3; head -n1 <&3")
[ "$reply" = "OK $FAKE" ] || fail "tcp scenario: got '$reply', want 'OK $FAKE'"

# The api log slices auth to 14 chars: 'Bearer ghp_de' proves the real
# token arrived; the fake's 14-char slice ('Bearer ghp_26') must be absent.
grep -q "auth=Bearer ghp_de" "$work/api.log" || fail "api never saw the real token"
if grep -q "auth=Bearer ghp_26" "$work/api.log"; then
  fail "api saw the fake token: capture did not substitute"
fi

echo "bwrap demo: all scenarios passed (fake never left the namespace)"
