## [0.1.22] - 2026-09-20

### 🚀 Features

- Flatten the workspace CLI, add agent --rm, fix eBPF self-exclusion in containers (#35)
## [0.1.21] - 2026-09-19

### 🚀 Features

- *(proxy)* Add wasm rewrite plugin system + proptest fuzz suite (#34)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.21 [ci skip]
- Release
## [0.1.20] - 2026-09-18

### 🚜 Refactor

- *(proxy)* [**breaking**] Replace hand-rolled TLS stack with rama + boring (#33)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.20 [ci skip]
- Release
## [0.1.19] - 2026-09-18

### ⚙️ Miscellaneous Tasks

- *(container)* Assert on markers that exist in the binary
- Update changelog for v0.1.19 [ci skip]
- Release
## [0.1.18] - 2026-09-18

### ⚙️ Miscellaneous Tasks

- *(dist)* Build only the root package in releases
- *(ci)* Update the nightly version
- *(mise)* Pin the nightly toolchain to a dated specifier
- Update changelog for v0.1.18 [ci skip]
- Release
## [0.1.17] - 2026-09-18

### 🚀 Features

- *(capture)* [**breaking**] Add ebpf transparent backend (#32)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.17 [ci skip]
- Release
## [0.1.16] - 2026-09-16

### 🚀 Features

- *(capture)* [**breaking**] Restore tun backend beside tproxy via --proxy-backend (#31)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.16 [ci skip]
- Release hodor version 0.1.16
## [0.1.15] - 2026-09-16

### 🚀 Features

- Workspace-scoped fnox decoy credential injection
- Cover crypto infra APIs, fix dead hosts
- *(confine)* Make init produce a runnable stack
- *(confine)* Wire the agent container runtime

### 📚 Documentation

- Add user docs, rewrite README

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.15 [ci skip]
- Release hodor version 0.1.15
## [0.1.14] - 2026-09-14

### 🚀 Features

- *(confine)* Compose-based workspace lifecycle

### 🐛 Bug Fixes

- Recover bwrap demo, docs, and image base lost in rebase

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.14 [ci skip]
- Release hodor version 0.1.14
## [0.1.13] - 2026-09-13

### 🚀 Features

- *(tproxy)* Kernel TPROXY capture replacing tun, with demo and guard

### ⚙️ Miscellaneous Tasks

- *(mise)* Restructure task files into namespaced dirs
- Update changelog for v0.1.13 [ci skip]
- Release hodor version 0.1.13
## [0.1.12] - 2026-09-12

### 🐛 Bug Fixes

- *(dist)* Install libudev-dev in the dist build setup

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.12 [ci skip]
- Release hodor version 0.1.12
## [0.1.11] - 2026-09-12

### 🚀 Features

- *(secrets)* Add the bundled host registry and rules.d overrides
- *(secrets)* Resolve rule hosts, patterns, and if_missing
- *(secrets)* Resolve rule values from fnox
- *(registry)* Seed known hosts for the first provider tranche

### 🐛 Bug Fixes

- *(secrets)* Distinguish missing, absent and empty fnox values
- *(ci)* Install libudev-dev for the fnox-core dep tree

### 📚 Documentation

- Add the rules and registry spec and plan
- Fix the dead Azure source link in the plan
- Document rules, the registry, and fnox values
- Correct the registry layer precedence
- Apply markdown formatting to AGENTS.md
- *(registry)* Mark the undocumented environment names

### 🚜 Refactor

- *(config)* Rename [secrets] to [rules] and open the schema
- *(secrets)* Chain errors and drop needless clones
- *(config)* Chain the rule-merge errors

### ⚙️ Miscellaneous Tasks

- *(mise)* Pin node lts in the toolchain
- Update changelog for v0.1.11 [ci skip]
- Release hodor version 0.1.11
## [0.1.10] - 2026-09-11

### 🐛 Bug Fixes

- *(dist)* Build the released binaries with the tun feature

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.10 [ci skip]
- Release hodor version 0.1.10
## [0.1.9] - 2026-09-11

### 🚀 Features

- *(ca)* Write the certificate and key beside the CA file

### ⚙️ Miscellaneous Tasks

- *(heimdall)* Point the policy messages at the format task
- Update changelog for v0.1.9 [ci skip]
- Release hodor version 0.1.9
## [0.1.8] - 2026-09-11

### ⚙️ Miscellaneous Tasks

- *(ci)* Use current action majors in the hand-written workflows
- Update changelog for v0.1.8 [ci skip]
- Release hodor version 0.1.8
## [0.1.7] - 2026-09-11

### 🐛 Bug Fixes

- *(container)* Check out the repo so buildx can find the Dockerfile

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.7 [ci skip]
- Release hodor version 0.1.7
## [0.1.6] - 2026-09-11

### 🐛 Bug Fixes

- *(container)* Download and extract the release asset correctly

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.6 [ci skip]
- Release hodor version 0.1.6
## [0.1.5] - 2026-09-11

### 🐛 Bug Fixes

- *(dist)* Add the profile cargo-dist builds with

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.5 [ci skip]
- Release hodor version 0.1.5
## [0.1.4] - 2026-09-11

### 🐛 Bug Fixes

- *(ci)* Grant the container job the permissions it requests

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.4 [ci skip]
- Release hodor version 0.1.4
## [0.1.3] - 2026-09-11

### 🐛 Bug Fixes

- *(proxy)* Treat missing TLS close_notify as clean EOF

### 📚 Documentation

- Add an agentic devenv example
- Rewrite the README for users

### ⚙️ Miscellaneous Tasks

- *(mise)* Split tun test task into user build + root exec
- Initial import
- Update changelog for v0.1.1 [ci skip]
- Release hodor version 0.1.1
- Update changelog for v0.1.2 [ci skip]
- Release hodor version 0.1.2
- Publish the image on main and use it in the example
- Build the image from the repo root with an explicit Dockerfile
- Update changelog for v0.1.3 [ci skip]
- Release hodor version 0.1.3
