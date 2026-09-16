# How to extend the known-host registry

This guide shows you how to teach hodor about a private API endpoint, a self-hosted control plane, or a token shape it does not know. You need the env var name, the host that may receive the real value, and roughly what the token looks like.

hodor ships a bundled table mapping known services to their env names, API hosts, and token shapes, so most rules need nothing beyond `env`. When a name is not in the table, or the table is wrong for your deployment, override it with a `rules.d` file rather than repeating `allow` in every rule.

## 1. Pick the file location

Two override directories, both loaded in filename order:

- Global: `<config-dir>/hodor/rules.d/*.toml`, beside the global config file. Applies to every workspace.
- Project: `<workspace-root>/.config/hodor/rules.d/*.toml`. Applies to one workspace.

Project entries override global ones, which override the bundled table.

## 2. Add a provider entry

```toml
# <config-dir>/hodor/rules.d/acme.toml
[providers.acme]
env = ["ACME_API_KEY"]
hosts = ["https://api.acme.example.com"]
pattern = "acme_{hex:32}"
```

| Field | Meaning |
| --- | --- |
| `env` | Env var names this provider owns. |
| `hosts` | `scheme://host[:port]` allow entries granted to every listed name. A per-tenant endpoint uses a `*.`-suffix host family. |
| `pattern` | Decoy shape for these names. |
| `contains` | Substrings matched against lowercased env names to select a decoy shape only, never hosts. |
| `replace` | `true` discards what earlier layers declared for these names, then applies this entry's fields. |

A rule referencing the name now inherits the hosts and the shape:

```toml
[rules.acme]
env = "ACME_API_KEY"
```

## 3. Or add a name-only entry

When only the hosts need overriding, a names entry is the smaller change:

```toml
[names.GH_ENTERPRISE_TOKEN]
hosts = ["https://ghe.corp.example"]
```

## 4. Preview the decoy

`hodor fake` uses the same table, so the override is visible without running a proxy:

```sh
hodor fake ACME_API_KEY
# acme_1f4a9c...  (matches the pattern above)
```

## How conflicts resolve

Within one registry file, the pattern lookup order is an explicit `pattern` in the rule, then `[names.<ENV>]`, then a `[providers.*]` entry claiming the env name, then `contains`, then the default `{hex:32}`.

Across files, a later load's pattern overrides an earlier one regardless of tier, because the bundled table loads first and `rules.d` files load in filename order. The one exception is `contains`: matches are tried in load order, so the earliest-loaded file wins, and within one file the first provider name in sort order wins. A `contains` needle from a bundled provider therefore beats a `rules.d` needle under a different provider name. Set `replace = true` on your provider entry to discard its earlier `contains` needles first.

See [the registry reference](../reference/registry.md) for the full format.
