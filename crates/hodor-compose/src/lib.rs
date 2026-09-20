//! Workspace confinement: `hodor rules` prints env-only rules for the
//! fnox-declared names the registry knows; `hodor init` generates the
//! workspace stack once as an editable file; `hodor up`/`down`/`logs` drive
//! the layered compose project; `hodor agent` runs that whole sequence
//! in one go.

mod confine;
mod paths;
mod stack;

pub use confine::{agent_command, down_command, init_command, logs_command, up_command};
pub use stack::rules_command;

#[cfg(test)]
mod tests {
  use std::collections::BTreeMap;
  use std::ffi::OsString;
  use std::path::{Path, PathBuf};

  use hodor_config::cli::{LogsArgs, ProxyBackend};
  use hodor_config::config::AgentCfg;

  use crate::confine::*;
  use crate::paths::*;
  use crate::stack::*;

  fn decoys() -> Vec<Decoy> {
    vec![
      Decoy {
        env: "GITHUB_TOKEN".to_string(),
        value: "ghp_2641386f5e0c6b9ea7b79c738a1015a9bc3a9ae3".to_string(),
      },
      Decoy {
        env: "ANTHROPIC_API_KEY".to_string(),
        value: "sk-ant-api03-example".to_string(),
      },
    ]
  }

  fn mount(host: &str, container: &str, ro: bool) -> Mount {
    Mount {
      host: PathBuf::from(host),
      container: PathBuf::from(container),
      ro,
    }
  }

  /// Test agent spec: `root` inside the container, home `/home/eng`, and the
  /// workspace-state storage directory the agent service mounts.
  fn agent_paths(root: &'static str) -> AgentSpec<'static> {
    AgentSpec {
      root: Path::new(root),
      home: "/home/eng",
      storage: Path::new("/state/hodor/ws/hodor/containers"),
      uid: 1000,
    }
  }

  /// A default-ish stack to render in tests; override fields struct-update style.
  fn test_stack(backend: ProxyBackend) -> Stack<'static> {
    Stack {
      backend,
      project: "hodor".to_string(),
      decoys: decoys(),
      agent: agent_paths("/home/eng"),
      mounts: Vec::new(),
      agent_configs: Vec::new(),
      fnox: FnoxBinds::default(),
      init: None,
    }
  }

  /// Test-only env write and removal, so the unsafe call lives in one place.
  fn set_env(key: &str, value: impl AsRef<std::ffi::OsStr>) {
    // SAFETY: test-only mutation, and nextest runs one test per process.
    unsafe { std::env::set_var(key, value) };
  }

  fn unset_env(key: &str) {
    // SAFETY: test-only mutation, and nextest runs one test per process.
    unsafe { std::env::remove_var(key) };
  }

  #[test]
  fn rules_toml_lists_every_env_without_values() {
    let toml = rules_toml(&decoys(), &[], &[]);
    assert!(toml.contains("[rules.github_token]"), "{toml}");
    assert!(toml.contains("env = \"GITHUB_TOKEN\""), "{toml}");
    assert!(toml.contains("[rules.anthropic_api_key]"), "{toml}");
    assert!(toml.contains("#   allow = [\"https://api.internal.example.com\"]"), "{toml}");
    assert!(!toml.contains("value ="), "{toml}");
  }

  #[test]
  fn names_the_registry_states_no_hosts_for_split_out_of_the_active_rules() {
    let registry = generation_registry().unwrap();
    let decoys = vec![
      Decoy {
        env: "GITHUB_TOKEN".to_string(),
        value: "decoy".to_string(),
      },
      Decoy {
        env: "VAULT_TOKEN".to_string(),
        value: "decoy".to_string(),
      },
    ];
    let (with_hosts, hostless) = by_hosts(&registry, decoys);
    assert_eq!(with_hosts.len(), 1);
    assert_eq!(with_hosts[0].env, "GITHUB_TOKEN");
    assert_eq!(hostless.len(), 1);
    assert_eq!(hostless[0].env, "VAULT_TOKEN");
  }

  #[test]
  fn rules_toml_comments_out_names_the_registry_knows_without_hosts() {
    let hostless = vec![Decoy {
      env: "ARGO_CD_TOKEN".to_string(),
      value: "decoy".to_string(),
    }];
    let toml = rules_toml(&decoys(), &hostless, &["TAVILY_API_KEY".to_string()]);
    assert!(toml.contains("# [rules.argo_cd_token]"), "{toml}");
    assert!(toml.contains("# env = \"ARGO_CD_TOKEN\""), "{toml}");
    assert!(toml.contains("# allow = [\"https://<your-host>\"]"), "{toml}");
    assert!(!toml.contains("\n[rules.argo_cd_token]"), "{toml}");
    assert!(toml.contains("# TAVILY_API_KEY"), "{toml}");
  }

  #[test]
  fn under_home_paths_translate_into_the_container_home() {
    let host_home = Path::new("/home/ivan");
    assert_eq!(
      translate(Path::new("/home/ivan/github/hodor"), Some(host_home), "/home/eng"),
      PathBuf::from("/home/eng/github/hodor")
    );
    assert_eq!(translate(Path::new("/data"), Some(host_home), "/home/eng"), PathBuf::from("/data"));
    assert_eq!(
      translate(Path::new("/home/ivan"), Some(host_home), "/home/eng"),
      PathBuf::from("/home/eng")
    );
  }

  #[test]
  fn covering_mounts_absorb_overlaps() {
    let mounts = vec![
      mount("/home/ivan/github/hodor", "/home/eng/github/hodor", false),
      mount("/home/ivan/github", "/home/eng/github", false),
      mount("/home/ivan/.config/mise", "/home/eng/.config/mise", true),
      mount("/opt/data", "/opt/data", false),
    ];
    let kept = covering(mounts);
    let hosts: Vec<String> = kept.iter().map(|m| m.host.display().to_string()).collect();
    assert_eq!(hosts, vec!["/home/ivan/github", "/home/ivan/.config/mise", "/opt/data"], "{kept:?}");
    assert!(kept[1].ro, "the surviving mount keeps its own mode");
  }

  #[test]
  fn include_entries_split_their_mount_mode() {
    assert_eq!(split_mode(Path::new("~/.config/mise:ro")), (PathBuf::from("~/.config/mise"), true));
    assert_eq!(split_mode(Path::new("/data/cache:rw")), (PathBuf::from("/data/cache"), false));
    assert_eq!(split_mode(Path::new("/data/cache")), (PathBuf::from("/data/cache"), false));
  }

  #[test]
  fn tilde_and_relative_includes_expand_against_root_and_home() {
    let root = Path::new("/home/ivan/github/hodor");
    let host_home = Some(Path::new("/home/ivan"));
    assert_eq!(
      expand(Path::new("~/.config/mise"), root, host_home),
      PathBuf::from("/home/ivan/.config/mise")
    );
    assert_eq!(
      expand(Path::new("../sibling"), root, host_home),
      PathBuf::from("/home/ivan/github/sibling")
    );
    assert_eq!(expand(Path::new("/opt/data"), root, host_home), PathBuf::from("/opt/data"));
  }

  #[test]
  fn agent_config_directories_mount_at_each_agents_default_location() {
    let host_home = tempfile::tempdir().unwrap();
    let config_dir = host_home.path().join(".config").join("hodor");
    let agents = config_dir.join("agents");
    std::fs::create_dir_all(agents.join("pi")).unwrap();
    std::fs::create_dir_all(agents.join("opencode")).unwrap();
    std::fs::create_dir_all(agents.join("not-an-agent")).unwrap();
    std::fs::write(agents.join("stray-file"), "x").unwrap();

    let mounts = agent_config_mounts(Some(&config_dir), &BTreeMap::new(), "/home/eng").unwrap();
    let rendered: Vec<String> = mounts
      .iter()
      .map(|entry| {
        format!(
          "{}:{}:{}",
          entry.host.display(),
          entry.container.display(),
          if entry.ro { "ro" } else { "rw" }
        )
      })
      .collect();
    assert_eq!(
      rendered,
      vec![
        format!("{}:/home/eng/.config/opencode:rw", agents.join("opencode").display()),
        format!("{}:/home/eng/.pi:rw", agents.join("pi").display()),
      ]
    );

    let yaml = Stack {
      agent: agent_paths("/home/eng/github/hodor"),
      agent_configs: mounts.clone(),
      ..test_stack(ProxyBackend::Tproxy)
    }
    .render();
    assert!(
      yaml.contains(&format!("- {}:/home/eng/.pi:rw", agents.join("pi").display())),
      "{yaml}"
    );
    assert!(!yaml.contains("not-an-agent"), "{yaml}");
  }

  #[test]
  fn configured_agents_extend_and_override_the_built_in_table() {
    let host_home = tempfile::tempdir().unwrap();
    let config_dir = host_home.path().join(".config").join("hodor");
    let agents = config_dir.join("agents");
    std::fs::create_dir_all(agents.join("pi")).unwrap();
    std::fs::create_dir_all(agents.join("trae")).unwrap();

    let configured = BTreeMap::from([
      (
        "pi".to_string(),
        AgentCfg {
          config_dir: "{home}/.pi-alt".to_string(),
        },
      ),
      (
        "trae".to_string(),
        AgentCfg {
          config_dir: "{home}/.trae".to_string(),
        },
      ),
    ]);
    let mounts = agent_config_mounts(Some(&config_dir), &configured, "/home/eng").unwrap();
    let rendered: Vec<String> = mounts
      .iter()
      .map(|entry| format!("{}:{}", entry.host.display(), entry.container.display()))
      .collect();
    assert_eq!(
      rendered,
      vec![
        format!("{}:/home/eng/.pi-alt", agents.join("pi").display()),
        format!("{}:/home/eng/.trae", agents.join("trae").display()),
      ]
    );

    let relative = BTreeMap::from([(
      "pi".to_string(),
      AgentCfg {
        config_dir: "relative/pi".to_string(),
      },
    )]);
    let err = agent_config_mounts(Some(&config_dir), &relative, "/home/eng").unwrap_err();
    assert!(err.to_string().contains("absolute"), "{err:?}");
  }

  #[test]
  fn the_agent_service_carries_what_inner_containers_need() {
    let yaml = test_stack(ProxyBackend::Tproxy).render();
    for expected in [
      "image: ghcr.io/casualjim/devagent:26.04",
      "security_opt: [seccomp=unconfined, systempaths=unconfined, apparmor=unconfined]",
      "cap_add: [SYS_CHROOT, AUDIT_WRITE, NET_ADMIN, SETUID, SETGID, SYS_ADMIN]",
      "devices: [/dev/net/tun]",
      "user: \"1000\"",
      "- /state/hodor/ws/hodor/containers:/home/eng/.local/share/containers",
    ] {
      assert!(yaml.contains(expected), "missing {expected}:\n{yaml}");
    }
    // The agent runs its own runtime; it never reaches the host's.
    assert!(!yaml.contains("docker.sock") && !yaml.contains("/var/run/docker"), "{yaml}");
  }

  #[test]
  fn compose_yaml_indents_every_mapping_key_under_its_parent() {
    // The generated stack is parsed by docker's YAML loader, so a key at the
    // wrong depth is a hard failure, not a cosmetic one. In these literals a
    // `\`-continued line drops its leading whitespace while the first line
    // keeps it, which is how `cap_add:` once landed at nine spaces inside
    // `environment:` and `hodor up` died with "did not find expected key".
    let yaml = test_stack(ProxyBackend::Tproxy).render();
    for expected in [
      "\n    cap_add:\n      - NET_ADMIN\n",
      "\n    stop_grace_period: 1s\n",
      "\n    volumes:\n",
      "\n  agent:\n",
      "\n  hodor:\n",
      "\nservices:\n",
    ] {
      assert!(yaml.contains(expected), "missing {expected:?}:\n{yaml}");
    }
  }

  #[test]
  fn compose_yaml_mounts_the_workspace_at_its_translated_path() {
    let mounts = vec![
      mount("/home/ivan/github/hodor", "/home/eng/github/hodor", false),
      mount("/home/ivan/.config/mise", "/home/eng/.config/mise", true),
    ];
    let yaml = Stack {
      agent: agent_paths("/home/eng/github/hodor"),
      mounts: mounts.clone(),
      ..test_stack(ProxyBackend::Tproxy)
    }
    .render();
    assert!(yaml.contains("name: hodor\nservices:"), "{yaml}");
    assert!(yaml.contains("working_dir: \"/home/eng/github/hodor\""), "{yaml}");
    assert!(yaml.contains("- /home/ivan/github/hodor:/home/eng/github/hodor:rw"), "{yaml}");
    assert!(yaml.contains("- /home/ivan/.config/mise:/home/eng/.config/mise:ro"), "{yaml}");
    assert!(
      yaml.contains("entrypoint: [\"/home/eng/.config/hodor/agent-entrypoint.sh\"]"),
      "the entrypoint is the in-container path: {yaml}"
    );
    assert!(
      yaml.contains(":/home/eng/.config/hodor/agent-entrypoint.sh:ro"),
      "mounted where the entrypoint names it: {yaml}"
    );
    assert!(yaml.contains("network_mode: \"service:hodor\""), "{yaml}");
    assert!(yaml.contains(":/certs/ca.pem"), "the CA is mounted for hodor: {yaml}");
    assert!(!yaml.contains("/root/.config/fnox"), "no fnox mount without binds to mount: {yaml}");
    assert!(yaml.contains("init: true"), "{yaml}");
    assert!(
      yaml.contains("GITHUB_TOKEN: \"ghp_2641386f5e0c6b9ea7b79c738a1015a9bc3a9ae3\""),
      "{yaml}"
    );
  }

  #[test]
  fn workspace_slug_uses_path_segments() {
    assert_eq!(workspace_slug(Path::new("/home/ivan/github/hodor")), "home-ivan-github-hodor");
    assert_eq!(workspace_slug(Path::new("/srv/My_Project")), "srv-my-project");
  }

  #[test]
  fn the_example_workspace_loads_and_inherits_registry_hosts() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/agentic-devenv/.config/hodor.toml");
    let cli = hodor_config::cli::Cli {
      config: Some(example.clone()),
      command: None,
    };
    let (config, _) = hodor_config::config::load(&cli).unwrap_or_else(|err| panic!("{} does not load: {err}", example.display()));
    assert_eq!(config.workspace.home.as_deref(), Some("/home/eng"));
    assert_eq!(config.workspace.shell.as_deref(), Some("bash"));
    let registry = generation_registry().unwrap();
    for (label, env) in [("anthropic", "ANTHROPIC_API_KEY"), ("github", "GH_TOKEN")] {
      let rule = config
        .rules
        .get(label)
        .unwrap_or_else(|| panic!("`{label}` missing from {}", example.display()));
      assert_eq!(rule.env, env);
      assert!(rule.value.is_none(), "`{label}` must resolve from fnox, not carry a value");
      assert!(!registry.hosts_for(rule).is_empty(), "`{label}` needs hosts from the registry");
    }
  }

  #[test]
  fn includes_that_are_not_there_are_rejected() {
    let host_home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let sibling = root.path().join("sibling");
    std::fs::create_dir_all(&sibling).unwrap();

    let entries = include_entries(root.path(), &[PathBuf::from("sibling:ro")], Some(host_home.path())).unwrap();
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert!(entries.iter().any(|(path, ro)| path == &sibling && *ro), "{entries:?}");

    let err = include_entries(root.path(), &[PathBuf::from("missing")], Some(host_home.path())).unwrap_err();
    assert!(err.to_string().contains("does not exist"), "{err:?}");
    assert!(err.to_string().contains("missing"), "{err:?}");
  }

  #[test]
  fn fnox_binds_mount_only_what_exists_and_forward_present_credentials() {
    let home = tempfile::tempdir().unwrap();
    let config_dir = tempfile::tempdir().unwrap();
    let fnox_dir = home.path().join(".config").join("fnox");
    std::fs::create_dir_all(&fnox_dir).unwrap();
    std::fs::write(fnox_dir.join("age.txt"), "AGE-SECRET-KEY-1\n").unwrap();
    std::fs::write(
      config_dir.path().join("fnox.toml"),
      "[secrets.X]\nprovider = \"plain\"\nvalue = \"x\"\n",
    )
    .unwrap();
    std::fs::write(config_dir.path().join("config.toml"), "[proxy]\n").unwrap();

    let binds = fnox_binds(Some(&fnox_dir), Some(config_dir.path()));
    let rendered: Vec<String> = binds
      .mounts
      .iter()
      .map(|entry| format!("{}:{}:ro", entry.host.display(), entry.container.display()))
      .collect();
    assert_eq!(
      rendered,
      vec![
        format!("{}:/root/.config/fnox:ro", fnox_dir.display()),
        format!("{}:/root/.config/hodor/fnox.toml:ro", config_dir.path().join("fnox.toml").display()),
      ],
      "the fnox config directory and hodor's own fnox level, and not the host's hodor config.toml"
    );

    let empty = tempfile::tempdir().unwrap();
    assert!(
      fnox_binds(Some(&empty.path().join("missing")), Some(empty.path()))
        .mounts
        .is_empty(),
      "a path that is not there is never mounted: docker would create a directory in its place"
    );

    // Credentials in the shell are not the proxy's business: whatever the
    // environment carries, the generated stack forwards nothing.
    let key = "BWS_ACCESS_TOKEN";
    let previous = std::env::var_os(key);
    set_env(key, "0.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let yaml = Stack {
      fnox: fnox_binds(None, None),
      ..test_stack(ProxyBackend::Tproxy)
    }
    .render();
    assert!(!yaml.contains("${"), "no environment interpolation survives generation: {yaml}");
    assert!(!yaml.contains(key), "the credential name is not forwarded either: {yaml}");
    assert!(
      !yaml.contains("0.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
      "the value must not be written"
    );
    match previous {
      Some(value) => set_env(key, value),
      None => unset_env(key),
    }
  }

  #[test]
  fn support_files_are_written_when_absent_and_stale_entrypoints_regenerate() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let entrypoint = dir.path().join("agent-entrypoint.sh");
    let storage = dir.path().join("state").join("containers");

    let files = ensure_support_files(dir.path(), &storage).unwrap();
    assert!(files.iter().all(|(_, created)| *created), "{files:?}");
    let pem = std::fs::read_to_string(dir.path().join("ca.pem")).unwrap();
    let crt = std::fs::read_to_string(dir.path().join("ca.crt")).unwrap();
    let key = std::fs::read_to_string(dir.path().join("ca.key")).unwrap();
    assert!(entrypoint.is_file());
    assert!(storage.is_dir(), "storage belongs to the workspace state, not the config dir");
    assert!(
      !dir.path().join("agent-containers").exists(),
      "no storage under the config dir: {files:?}"
    );
    // `ca.pem` is what hodor reads; `ca.crt` is the certificate alone, which is
    // what the agent gets. A clean system needs both.
    assert!(
      pem.contains("BEGIN CERTIFICATE") && pem.contains("PRIVATE KEY"),
      "ca.pem carries both halves"
    );
    assert!(
      crt.contains("BEGIN CERTIFICATE") && !crt.contains("PRIVATE KEY"),
      "ca.crt carries the certificate only"
    );
    assert!(
      key.contains("PRIVATE KEY") && !key.contains("CERTIFICATE"),
      "ca.key carries the key only"
    );
    let script = std::fs::read_to_string(&entrypoint).unwrap();
    assert!(
      script.contains("update-ca-certificates"),
      "the entrypoint installs the CA into the system store"
    );
    assert!(
      script.contains("${HODOR_INIT:-}") && script.contains("docker-entrypoint.sh"),
      "the entrypoint chains to the image's init: HODOR_INIT first, common names next"
    );
    assert!(script.contains("exec \"$@\""), "the entrypoint hands off to the command");
    assert_ne!(
      std::fs::metadata(&entrypoint).unwrap().permissions().mode() & 0o111,
      0,
      "the agent runs the entrypoint directly, so it must be executable"
    );

    std::fs::write(&entrypoint, "#!/bin/sh\necho mine\n").unwrap();
    std::fs::remove_file(dir.path().join("ca.pem")).unwrap();
    let files = ensure_support_files(dir.path(), &storage).unwrap();
    let created: BTreeMap<&str, bool> = files
      .iter()
      .map(|(path, created)| (path.file_name().unwrap().to_str().unwrap(), *created))
      .collect();
    assert_eq!(
      created.get("agent-entrypoint.sh"),
      Some(&false),
      "an edited entrypoint is replaced, not created anew"
    );
    assert_eq!(created.get("ca.pem"), Some(&true), "a deleted CA comes back");
    assert_eq!(
      std::fs::read_to_string(&entrypoint).unwrap(),
      ENTRYPOINT_SCRIPT,
      "a stale or edited entrypoint is regenerated"
    );
  }

  #[test]
  fn generated_decoys_follow_the_rule_pattern() {
    let registry = hodor_config::registry::Registry::load(None).unwrap();
    let default = registry.decoy("ANTHROPIC_API_KEY", None);
    let rule: hodor_config::config::RuleCfg =
      toml_edit::de::from_str("env = \"ANTHROPIC_API_KEY\"\npattern = \"sk-ant-api03-{hex:8}\"\n").unwrap();
    let rules = BTreeMap::from([("anthropic".to_string(), rule)]);

    let shaped = with_rule_patterns(
      vec![Decoy {
        env: "ANTHROPIC_API_KEY".to_string(),
        value: default.clone(),
      }],
      &registry,
      &rules,
    );

    assert_eq!(shaped[0].value, registry.decoy("ANTHROPIC_API_KEY", Some("sk-ant-api03-{hex:8}")));
    assert_ne!(shaped[0].value, default);
  }

  #[test]
  fn each_backend_shapes_the_serve_command_and_its_host_wiring() {
    let render = |backend| test_stack(backend).render();

    let tproxy = render(ProxyBackend::Tproxy);
    assert!(tproxy.contains("command: [\"serve\", \"--proxy-backend\", \"tproxy\"]"), "{tproxy}");
    assert_eq!(
      tproxy.matches("/dev/net/tun").count(),
      1,
      "only the agent service asks for the tun device: {tproxy}"
    );
    assert!(!tproxy.contains("cgroup"), "{tproxy}");

    let tun = render(ProxyBackend::Tun);
    assert!(tun.contains("command: [\"serve\", \"--proxy-backend\", \"tun\"]"), "{tun}");
    assert_eq!(tun.matches("/dev/net/tun").count(), 2, "hodor needs the tun device too: {tun}");
    assert!(!tun.contains("--ebpf-cgroup"), "{tun}");

    let ebpf = render(ProxyBackend::Ebpf);
    assert!(
      ebpf.contains("command: [\"serve\", \"--proxy-backend\", \"ebpf\", \"--ebpf-cgroup\", \"enclosing\"]"),
      "{ebpf}"
    );
    for expected in ["    cgroup: host\n", "      - BPF\n      - PERFMON\n"] {
      assert!(ebpf.contains(expected), "missing {expected:?}:\n{ebpf}");
    }
    assert_eq!(
      ebpf.matches("    cgroup_parent: hodor-hodor.slice\n").count(),
      2,
      "both services carry the shared cgroup, so docker creates it as hodor starts: {ebpf}"
    );
    assert!(
      !ebpf.contains("/sys/fs/cgroup"),
      "no host cgroup path is written down; the daemon's cgroup root decides where the shared cgroup lands: {ebpf}"
    );
    assert_eq!(ebpf.matches("/dev/net/tun").count(), 1, "ebpf needs no tun device: {ebpf}");
  }

  #[test]
  fn workspace_init_names_the_agent_images_init_script() {
    let yaml = Stack {
      init: Some("/usr/local/bin/devagent-entrypoint".to_string()),
      ..test_stack(ProxyBackend::Tproxy)
    }
    .render();
    assert!(
      yaml.contains("      HODOR_INIT: \"/usr/local/bin/devagent-entrypoint\"\n"),
      "the entrypoint chains to the image's init through HODOR_INIT: {yaml}"
    );
  }

  #[test]
  fn the_backend_defaults_to_ebpf_on_linux_and_none_is_refused() {
    #[cfg(target_os = "linux")]
    assert_eq!(resolve_backend(None).unwrap(), ProxyBackend::Ebpf);
    #[cfg(not(target_os = "linux"))]
    assert!(resolve_backend(None).is_err(), "no capture backend exists outside Linux");

    assert_eq!(resolve_backend(Some(ProxyBackend::Tun)).unwrap(), ProxyBackend::Tun);
    let err = resolve_backend(Some(ProxyBackend::None)).unwrap_err();
    assert!(err.to_string().contains("none"), "{err:?}");
  }

  /// `init` writes the workspace config once and never overwrites it: a stack
  /// that cannot substitute anything is worse than no stack, and an edited
  /// rules file is the user's.
  #[test]
  fn the_workspace_config_is_written_once_and_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".config").join("hodor.toml");

    assert!(write_if_absent(&path, "[rules.x]\n").unwrap(), "first write lands");
    assert!(
      !write_if_absent(&path, "something else\n").unwrap(),
      "an existing file is left alone"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "[rules.x]\n");
  }

  /// Regeneration keys off the workspace config: a stack generated before a
  /// rule existed holds decoys that can never be swapped, and a stack with no
  /// digest beside it predates the check.
  #[test]
  fn the_stack_is_stale_until_its_digest_matches_the_workspace_config() {
    let root = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let config = root.path().join(".config");
    std::fs::create_dir_all(&config).unwrap();

    assert!(
      stack_is_stale(state.path(), root.path()),
      "no digest means the stack predates the check"
    );
    std::fs::write(state.path().join("config.digest"), config_digest(root.path()).to_string()).unwrap();
    assert!(!stack_is_stale(state.path(), root.path()), "an untouched config keeps the stack");

    std::fs::write(config.join("hodor.toml"), "[rules.x]\nenv = \"X\"\n").unwrap();
    assert!(
      stack_is_stale(state.path(), root.path()),
      "a config that appeared after generation is a change"
    );
    std::fs::write(state.path().join("config.digest"), config_digest(root.path()).to_string()).unwrap();
    assert!(!stack_is_stale(state.path(), root.path()));
  }

  /// Generation reads the global layer too, so an edit there — where `[workspace]`
  /// settings like `init` live — must regenerate the stack, not just workspace edits.
  #[test]
  fn the_stack_is_stale_when_the_global_config_changes() {
    let root = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let global = tempfile::tempdir().unwrap();
    set_env("XDG_CONFIG_HOME", global.path());
    let hodor_dir = global.path().join("hodor");
    std::fs::create_dir_all(&hodor_dir).unwrap();

    std::fs::write(state.path().join("config.digest"), config_digest(root.path()).to_string()).unwrap();
    assert!(!stack_is_stale(state.path(), root.path()), "absent global layer is stable");

    std::fs::write(hodor_dir.join("config.toml"), "[workspace]\ninit = \"/init\"\n").unwrap();
    assert!(
      stack_is_stale(state.path(), root.path()),
      "a global config that appeared after generation is a change"
    );
    std::fs::write(state.path().join("config.digest"), config_digest(root.path()).to_string()).unwrap();
    assert!(!stack_is_stale(state.path(), root.path()));

    std::fs::write(hodor_dir.join("config.toml"), "[workspace]\ninit = \"/init2\"\n").unwrap();
    assert!(stack_is_stale(state.path(), root.path()), "a global config edit is a change");
    unset_env("XDG_CONFIG_HOME");
  }

  /// A regeneration must not switch how traffic is captured: the backend is
  /// read back off the compose file, and the caller's default is only a
  /// fallback.
  #[test]
  fn the_generated_stack_reports_its_backend() {
    assert_eq!(
      generated_backend("      command: [\"serve\", \"--proxy-backend\", \"tun\"]\n"),
      Some(ProxyBackend::Tun)
    );
    assert_eq!(generated_backend("\"--proxy-backend\", \"ebpf\""), Some(ProxyBackend::Ebpf));
    assert_eq!(generated_backend("\"--proxy-backend\", \"tproxy\""), Some(ProxyBackend::Tproxy));
    assert_eq!(
      generated_backend("command: [\"serve\"]\n"),
      None,
      "a stack that names no backend keeps the caller's"
    );
  }

  /// Zero rules is the state that answers every provider with a decoy: it has
  /// to be said out loud rather than served silently.
  #[test]
  fn serving_no_rules_is_announced() {
    let config_file = Path::new("/ws/.config/hodor.toml");
    let warning = rules_warning(&BTreeMap::new(), config_file).expect("no rules is worth a warning");
    assert!(
      warning.contains("no [rules.*]") && warning.contains("/ws/.config/hodor.toml"),
      "{warning}"
    );

    let rules = BTreeMap::from([(
      "github".to_string(),
      toml_edit::de::from_str::<hodor_config::config::RuleCfg>("env = \"GH_TOKEN\"\n").unwrap(),
    )]);
    assert!(rules_warning(&rules, config_file).is_none(), "one rule is enough not to warn");
  }

  /// The flags map one-to-one onto compose's and services ride at the end: a
  /// wrong order here is a silently different log view, not an error.
  #[test]
  fn the_logs_command_maps_onto_compose_flags() {
    let bare = logs_argv(&LogsArgs {
      workspace: None,
      follow: false,
      no_log_prefix: false,
      tail: "all".into(),
      services: Vec::new(),
    });
    assert_eq!(bare, vec![OsString::from("logs"), OsString::from("--tail"), OsString::from("all")]);

    let full = logs_argv(&LogsArgs {
      workspace: Some(PathBuf::from("/srv/project")),
      follow: true,
      no_log_prefix: true,
      tail: "10".into(),
      services: vec!["hodor".into(), "agent".into()],
    });
    assert_eq!(
      full,
      ["logs", "--follow", "--no-log-prefix", "--tail", "10", "hodor", "agent"]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>()
    );
  }
}
