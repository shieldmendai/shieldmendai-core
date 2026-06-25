# Codex Handoff

- Product name: ShieldMendAi
- Objective: extract reusable monitoring and self-healing concepts into a clean,
  public, standalone project without exposing or changing private systems.
- Workspace path: `/root/ShieldMendAi`
- Read-only source path: `/root/newbasebot`
- Current phase: Phase 1 — read-only inventory and architecture
- Completed work: repository safety preflight; targeted source and systemd
  discovery; sanitized source inventory; architecture; security boundaries;
  ten-phase deployment path plus explicit legacy-retirement phase; dedicated
  server plan; manifest; read-only resume script; README and ignore hardening.
- Work in progress: local Phase 1 Git checkpoint and checkpoint-hash record.
- Exact next task: create the local Phase 1 documentation commit, then record
  that checkpoint hash in this handoff and the manifest.
- Blockers: systemd D-Bus access is unavailable in the sandbox, so discovery
  used read-only unit files under `/etc/systemd/system`; no implementation
  blocker for Phase 2.
- Safety restrictions: never modify the private source; never expose or copy
  credentials, wallets, trading logic, logs, reports, state, backups, databases,
  deny/quarantine data, or user data; never perform systemd write actions;
  never push without explicit authorization and a clean safety scan.
- Last checks and tests: manifest JSON parse; Bash syntax check; resume script;
  required-file check; Git whitespace/diff check; repository-only credential
  pattern and prohibited-artifact scan; expected-reference review; unchanged
  SHA-256 verification for 13 source files and 16 systemd definitions.
- Last local commit hash: `066efa61196fa803f29ef9012429a50424df4193`
- Remote status: `origin` fetch and push URLs match the official
  `shieldmendai/shieldmendai-core` repository; local branch has no configured
  upstream and started from the locally known `origin/main`.
- Push status: not pushed; pushing is prohibited during this Phase 1 run.
- UTC timestamp: 2026-06-25T04:07:34Z
