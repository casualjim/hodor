# Runtime-only image: the binary is built once in CI (amd64 + arm64) and
# copied in here; the container never compiles.
#
# BIN_DIR is where the binary sits in the build context. CI builds from the
# repository root and passes target/release. The release workflow unpacks the
# dist tarball into a context that holds the binary at its root, so the default
# is `.`.
#
# bare:libcxx-ssl = Ubuntu chisel rootfs (glibc, libc++, libssl, CA roots).
# No shell or package manager; policy routing goes through netlink, not `ip`.
FROM ghcr.io/casualjim/bare:libcxx-ssl
# TUN needs root (TUN device, policy routing, SO_MARK); root is in the chisel passwd db.
# hadolint ignore=DL3002,DL3066
USER root
ARG BIN_DIR=.
COPY ${BIN_DIR}/hodor /usr/local/bin/hodor
ENTRYPOINT ["hodor"]
CMD ["serve"]