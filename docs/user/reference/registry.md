# Registry reference

The bundled known-host registry: environment names, API hosts, and token shapes for the services hodor knows out of the box. The table lives in [`rules/registry.toml`](https://github.com/casualjim/hodor/blob/main/rules/registry.toml) in the repository; this page documents the format, which is the same for the bundled table and for overrides.

## Tables

### `[providers.<name>]`

One service entry.

```toml
[providers.github]
env      = ["GITHUB_TOKEN"]
hosts    = ["https://api.github.com", "https://ghe.corp.example"]
pattern  = "ghp_ghe_{hex:32}"
contains = ["gh_"]
replace  = false
```

| Field | Meaning |
| --- | --- |
| `env` | Env var names this provider owns. |
| `hosts` | `scheme://host[:port]` allow entries granted to every listed name. Stable API endpoints only; a per-tenant endpoint uses the host family its docs state (`https://*.example.com`). |
| `pattern` | Decoy shape for these names. Keeps the prefix a platform documents; where no format is documented, the shape approximates that platform's tokens. |
| `contains` | Substrings matched against lowercased env names. Selects a decoy shape only, never hosts. |
| `replace` | `true` discards what earlier layers declared for these names, then applies this entry's fields. |

### `[names.<ENV>]`

Hosts and pattern for a single env var, without inventing a provider. Useful for a one-off override:

```toml
[names.GH_ENTERPRISE_TOKEN]
hosts = ["https://ghe.corp.example"]
```

## Override locations

Two override directories, both loaded in filename order; project entries override global ones, which override the bundled table:

- Global: `<config-dir>/hodor/rules.d/*.toml`
- Project: `<workspace-root>/.config/hodor/rules.d/*.toml`

## Resolution rules

The pattern for a name resolves: rule `pattern`, then `[names.<ENV>]`, then the claiming `[providers.*]` entry, then `contains`, then `{hex:32}`. Across files, a later load's pattern wins regardless of tier. `contains` is the exception: earliest-loaded file wins, and `replace = true` is the way a later file takes a provider's needles back.

Hosts union across layers unless `replace = true` discards the earlier layers' hosts for those names.

`hodor fake <ENV>` uses the same table, so overrides preview without running a proxy. See [how to extend the registry](../how-to/extend-the-registry.md) for the workflow.
