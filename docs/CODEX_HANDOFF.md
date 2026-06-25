# Codex Handoff

- Product name: ShieldMendAi
- Objective: extract reusable monitoring and self-healing concepts into a clean,
  public, standalone project without exposing or changing private systems.
- Workspace path: `/root/ShieldMendAi`
- Read-only source path: `/root/newbasebot`
- Current phase: Phase 1 — read-only inventory and architecture, complete
- Completed work: repository safety preflight; targeted source and systemd
  discovery; sanitized source inventory; architecture; security boundaries;
  ten-phase deployment path plus explicit legacy-retirement phase; dedicated
  server plan; manifest; read-only resume script; README and ignore hardening.
- Work in progress: none; stop after the Phase 1 metadata checkpoint.
- Exact next task: in Phase 2, create the minimal `shieldmendai` Python package,
  typed configuration schema, and dry-run CLI skeleton without live monitors or
  repair execution.
- Blockers: none for Phase 2. Phase 1 systemd D-Bus access was unavailable in
  the sandbox, so discovery used read-only unit files under
  `/etc/systemd/system`.
- Safety restrictions: never modify the private source; never expose or copy
  credentials, wallets, trading logic, logs, reports, state, backups, databases,
  deny/quarantine data, or user data; never perform systemd write actions;
  never push without explicit authorization and a clean safety scan.
- Last checks and tests: manifest JSON parse; Bash syntax check; resume script;
  required-file check; Git whitespace/diff check; repository-only credential
  pattern and prohibited-artifact scan; expected-reference review; unchanged
  SHA-256 verification for 13 source files and 16 systemd definitions.
- Last local commit hash: `e3d89ecf8bbb0d8b94ff15a24a21e4bc3eaafeb2`
- Remote status: `origin` fetch and push URLs match the official
  `shieldmendai/shieldmendai-core` repository; local branch has no configured
  upstream and started from the locally known `origin/main`.
- Push status: not pushed; pushing is prohibited during this Phase 1 run.
- UTC timestamp: 2026-06-25T04:09:27Z
