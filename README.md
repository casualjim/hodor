# hodor

Grant-scoped MITM proxy. Terminates client TLS with per-domain leaf
certificates, swaps format-valid decoy fakes for real secret values only on
URI-grant match, and redacts values back to fakes on responses. Everything
else splices through byte-identical.

Optional TUN capture (`hodor serve --tun`, needs root) feeds guest packets
through a userspace TCP/IP stack into the same substitution path.

## Sanctioned tasks

```sh
mise run format    # linters + formatters (must be green)
mise run test      # full suite: default features, then --features tun (nextest)
mise run test:tun  # live TUN tests only: root + HODOR_TEST_TUN=1, serial threads
```

## Release flow

Mirrors [remark](https://github.com/casualjim/remark): CI gates land on
`main`, `Cut Release` bumps the version (via `bump:major/minor/patch` token),
git-cliff rewrites `CHANGELOG.md`, and `cargo-release` tags. The tag runs
`Release` (cargo-dist): builds `x86_64`/`aarch64` Linux binaries + shell
installer, uploads them to the GitHub release, then — as the final step of the
same pipeline — packs the just-published tarballs into the runtime-only
image (no compile in the Docker build) and pushes `ghcr.io/casualjim/hodor`
for both platforms.

Raw cargo works (`cargo test --features tun`) but the sanctioned path is
`mise run test` — it runs both feature sets.

## Acceptance coverage

No docker-compose harness yet. Closest in-repo proof of fake→real→fake:

- `tun_live_tcp_mitm_substitutes` (`src/tun.rs`, ignored): full TUN path,
  asserts the decoy goes upstream as the real secret and comes back redacted.
  Run via `mise run test:tun`.

License: Apache-2.0.
