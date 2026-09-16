# hodor user documentation

Pick by what you need right now. New here? Start with the tutorial.

| You want to | Go to |
| --- | --- |
| **Learn it, first time** | [Tutorial](tutorial.md) — one credential swap, end to end, both sides of the wire |
| **Get something done** | How-to guides, below |
| **Look something up while working** | Reference, below |
| **Understand why it works this way** | Explanation, below |

## How-to guides

Directions for a working practitioner, one goal each:

- [Confine a workspace](how-to/confine-a-workspace.md) — run a coding agent in a container that holds only decoys.
- [Capture traffic transparently](how-to/capture-traffic-transparently.md) — TPROXY or TUN capture, no client proxy setting, no bypass.
- [Get values from fnox](how-to/get-values-from-fnox.md) — keep real secrets out of hodor's config entirely.
- [Extend the known-host registry](how-to/extend-the-registry.md) — teach hodor a private endpoint or token shape.
- [Trust the hodor CA](how-to/trust-the-ca.md) — make clients and containers accept the intercepting certificate.

## Reference

Facts, austere and complete:

- [CLI](reference/cli.md) — every subcommand, flag, environment variable.
- [Configuration](reference/configuration.md) — the four layers and every key.
- [Allow entries](reference/allow-entries.md) — grant syntax and matching rules.
- [Decoy patterns](reference/decoy-patterns.md) — pattern verbs and selection order.
- [Registry](reference/registry.md) — the bundled known-host table and its override format.

## Explanation

The why behind the machinery:

- [How hodor works](explanation/how-it-works.md) — the life of a connection, splice versus substitution, and why each piece is shaped as it is.
- [The security model](explanation/security-model.md) — what hodor defends against, what it does not, and the edges you accept.
