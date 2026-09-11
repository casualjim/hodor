# Rules and registry: fnox-sourced values and known hosts

Date: 2026-09-11

## Problem

`[secrets.<label>]` entries today require three things written out by hand:
the real value inline in plaintext TOML, an `allow` list of hosts, and a
fake pattern when the auto-detected one is wrong. The plaintext value is
the worst of the three: hodor exists so a workload never holds the real
credential, yet its own config file does.

Two changes remove that:

1. Values come from fnox, which resolves them from age, 1Password, AWS
   Secrets Manager, Vault, Bitwarden, the OS keychain, and the rest of its
   provider catalog. hodor embeds `fnox-core` and resolves at startup.
2. Hosts and token shapes come from a bundled registry of known services,
   overridable from a drop-in directory. `env = "GITHUB_TOKEN"` alone then
   yields the right hosts and the right decoy shape.

The table is renamed `[rules.<label>]`, not `[secrets.<label>]`. A rule
wires an environment name to hosts, a decoy shape, and a value source; it
is not a declaration of a secret value.

## Non-goals

- No reimplementation of fnox's own proxying (`fnox proxy`, `[[proxy.rules]]`).
  hodor keeps its own MITM, body substitution, raw TCP, and TUN capture.
- No `hodor secrets` / `hodor doctor` subcommand in this change.
- No backward compatibility for `[secrets]`. The project is days old with
  no users; the rename is clean and carries no migration shim.
- No project-layer `rules.d`. The drop-in directory lives only in the
  user config dir.

## Config schema

```toml
[fnox]
config  = "/path/to/fnox.toml"   # optional; default: fnox's own discovery
profile = "work,default"         # optional; comma-separated, fnox semantics

[rules.gh]
env        = "GITHUB_TOKEN"        # required: fake seed, registry key, env var name
value      = "..."                 # optional: inline real value (escape hatch, local dev)
fnox_key   = "..."                 # optional: fnox secret name, default = env
allow      = ["https://ghe.corp"]  # optional: unions with registry hosts
pattern    = "..."                 # optional: overrides registry pattern
registry   = false                 # optional: skip registry hosts for this rule
if_missing = "error"               # "error" (default) | "warn" | "ignore"
```

`RuleCfg` replaces `SecretCfg` and `AppConfig.rules` replaces
`AppConfig.secrets`. The label stays a free-form log identifier; `env` is
the identity used for the decoy seed, the registry lookup, and the default
fnox key.

`[fnox]` is a nested struct, so `HODOR_FNOX_CONFIG` and `HODOR_FNOX_PROFILE`
come along through confique's env layer like the rest of the config.

## Registry schema

Bundled: `rules/registry.toml`, embedded with `include_str!`.
Overrides: `<config-dir>/hodor/rules.d/*.toml`, loaded in filename order,
later file wins. Both use the same schema:

```toml
[providers.github]
env      = ["GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT"]
hosts    = ["https://api.github.com", "https://github.com", "https://uploads.github.com"]
pattern  = "ghp_{hex:36}"
contains = ["gh_"]
replace  = false

[names.GH_ENTERPRISE_TOKEN]
hosts   = ["https://ghe.corp.example"]
replace = false
```

- `providers.<name>` — one entry per service. `env` lists the environment
  names it claims; `hosts` and `pattern` apply to all of them.
- `contains` — case-insensitive substrings of an environment name that
  select this provider's **pattern only**, never its hosts. This is where
  the current `PATTERNS` heuristics live, so a name like
  `ACME_ANTHROPIC_KEY` still gets an Anthropic-shaped decoy without
  silently gaining Anthropic hosts.
- `names.<ENV>` — a standalone entry keyed by an exact environment name,
  for overrides and for hosts no provider entry covers.
- `replace` — when true, this entry discards everything earlier layers
  declared for the same key before applying. Additive otherwise: hosts
  union, `pattern` takes the later value.

Hosts parse through the existing `UriGrant` validation (authority only, no
path, query, or userinfo). Patterns parse through the existing
`validate_pattern`. Two `providers` entries in the same layer claiming the
same environment name is an error, since that is a data bug. A
`names.<ENV>` entry in the same layer as a provider that claims that name
is not a bug — it is the intended override, and layers on top.

Lookup produces `env_name -> {hosts, pattern}` plus an ordered `contains`
list. When more than one provider's `contains` matches, the first in
provider-name order wins — TOML tables deserialize into `BTreeMap`, so
declaration order is not preserved.

## Resolution

`config::load` stays a pure file overlay: no keyring, no network, no fnox,
still unit-testable in isolation. A new `secrets::resolve` runs in `main`
before `grants::resolve`, and only for `serve`. `hodor fake` and `hodor ca`
never open fnox.

Per rule, in order:

| Field | Precedence |
| --- | --- |
| value | inline `value` → fnox |
| hosts | registry hosts (unless `registry = false`) ∪ explicit `allow` |
| pattern | explicit `pattern` → `names.<env>` → `providers.*` claim → `contains` tier → `{hex:32}` |

fnox is opened lazily. If every rule has an inline `value`, fnox-core is
never called and a missing fnox config is not an error. When a rule does
need a value and discovery finds no fnox config at all, that rule follows
its `if_missing` policy like any other missing value.

fnox config selection: `[fnox].config` (or `HODOR_FNOX_CONFIG`) →
`Fnox::open(path)`; otherwise `Fnox::discover()`, which is fnox's own
upward `fnox.toml` walk layered over fnox's global config. hodor adds no
fnox layer of its own.

`[fnox].profile` maps to `with_profiles`; when unset, `FNOX_PROFILE` wins
through discovery, as it does for the fnox binary.

## Failure semantics

A rule is unresolved when it has no inline value and fnox does not declare
its key, or when it ends up with zero hosts.

- `if_missing = "error"` (default) — bail, naming the label, the `env`, and
  which half is missing (value or hosts).
- `if_missing = "warn"` — log a warning and drop that rule's grant.
- `if_missing = "ignore"` — drop silently.

Declared-but-unresolvable is always a hard error: a key fnox lists but
cannot decrypt or fetch is a broken setup, not a missing secret. This
distinction is why resolution checks `Fnox::list()` before `Fnox::get()`;
`get()` returns `SecretNotFound` for a key that is not declared at all.

An unreadable or invalid `rules.d` file, a bad host entry, or a bad pattern
is always a hard error at startup, like today's config validation.

## Observability

At startup, one log line per rule: label, `env`, host count, value source
(`inline` / `fnox` / `none`), and the fnox key when it differs from `env`.
Dropped rules log at warn. Real values never appear in logs, matching the
existing `secrecy::SecretString` discipline.

## CLI

`hodor fake <ENV> [--pattern]` is unchanged in shape and gains registry
awareness: it loads the bundled registry plus `rules.d` so a custom rule's
pattern can be previewed. It never opens fnox.

## Testing

New `secrets::tests`:

- registry load: bundled-only; `rules.d` additive override; `replace = true`;
  `names.<ENV>` override; duplicate name in one layer rejected.
- pattern tiers: explicit, name entry, provider claim, `contains`, default.
- hosts: registry hosts, `registry = false`, union with explicit `allow`.
- `if_missing`: all three outcomes, value-missing and hosts-missing.
- fnox: resolution against a temp `fnox.toml` using fnox's `plain` provider
  (no key material, no network); undeclared key follows `if_missing`;
  declared-but-unresolvable is an error; no `value` anywhere means fnox is
  never opened.

Updated: `config.rs` tests for the rename and optional `value`. Unchanged:
`grants.rs`, `substitute.rs`. `hodor fake` gains a test proving a registry
pattern applies with no fnox present.

No live fnox tests; everything runs from temp files.

## Research deliverable

`rules/registry.toml` is seeded with a first tranche of roughly thirty
providers. For each: the environment names the platform's own docs use, its
API hosts, and its token shape, each entry carrying a `# source: <url>`
comment so the data can be re-checked.

Candidates: github, gitlab, anthropic, openai, gemini, aws, azure, gcp,
cloudflare, digitalocean, hetzner, fly, vercel, netlify, heroku, stripe,
slack, twilio, sendgrid, postmark, resend, npm, pypi, huggingface, datadog,
sentry, grafana, mongodb-atlas, supabase, shopify.

Only services with stable API hosts belong here. Connection-string secrets
(`DATABASE_URL`, `REDIS_URL`) are out of scope: their host lives in the
value, not in a registry.

Expansion is data-only edits to `rules/registry.toml`; users cover the rest
through `rules.d` and explicit `allow`.

## Costs

`fnox-core` has no feature flags, so its dependency tree — aws-sdk-*,
azure_*, gcp, keepass, keyring, reqwest, tera, and roughly forty more
direct dependencies — joins hodor's build. MSRV 1.91.1 sits under hodor's
1.98.1 and the license is MIT, so neither blocks the build. Expect a
materially larger binary and slower cold builds; that is the accepted price
of resolving secrets in-process rather than shelling out.

## Files touched

| Path | Change |
| --- | --- |
| `src/secrets.rs` | new: registry load/merge, fnox resolution, rule resolution |
| `rules/registry.toml` | new: bundled provider table |
| `src/config.rs` | `[secrets]` → `[rules]`, `SecretCfg` → `RuleCfg`, `[fnox]`, optional `value` |
| `src/grants.rs` | `[rules]` rename; a rule with no resolved value is skipped with a warning rather than substituting an empty value |
| `src/main.rs` | `secrets::resolve` in `serve`; registry in `fake`; `ca` reads `ca_file` from the config instead of building grants |
| `Cargo.toml` | add `fnox-core`, `tokio` already present |
| `README.md` | config section, registry section, fnox section |
| `AGENTS.md` | module map and conventions |
| `integration/hodor.toml` | rename to `[rules.*]` |

## Deferred

- `hodor secrets` / `hodor doctor` for inspecting resolution.
- Reading fnox `[[proxy.rules]]` as a grant source.
- Registry entries for connection-string secrets.
- Project-layer `rules.d`.
