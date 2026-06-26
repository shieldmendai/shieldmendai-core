# Codex Handoff

- Product name: ShieldMendAi
- Workspace: `/root/ShieldMendAi`
- Current branch: `codex/extraction-phase-8`
- Current phase: Phase 8 deployment readiness fix
- Starting verified commit for the ownership follow-up: `3686cd374dafd4f72c904410ddce32da7cfbd559`

## Readiness Audit Result

The original Phase 8 package was not live-ready. The dedicated-server readiness
audit found that generated launcher and configuration files were written with
incorrect actual modes, the package was not importable outside the repository,
the generated launcher was not executable, and systemd referenced commands that
were not available in the live runtime. Dedicated-server testing then found a
live ownership defect: `canary-runtime-install-apply` could leave
`/opt/shieldmendai/venv/bin/shieldmendai` as `root:root 0750`, denying
execution to the `shieldmendai` service user.

The audit safely caught these blockers before live installation. No live
deployment occurred, the dedicated server was not contacted, SSH was not used,
no operating-system user was created, no `systemctl` command was run, and no
real installation was performed during this fix.

## Implemented In This Fix

- actual canary file-mode enforcement under explicit temporary roots:
  launchers/programs `0750`, configs `0640`, manifest/audit `0640`, systemd
  units `0644`
- manifest mode records now reflect actual file modes
- `src/shieldmendai/main.py` exits through `shieldmendai.cli:main`
- `src/shieldmendai/__main__.py` enables `python3 -m shieldmendai`
- offline runtime preview/apply commands for a local ShieldMendAi wheel only
- wheel validation for expected package name, expected version, checksum,
  path traversal, symlink escape, and conflicting runtime markers
- fixed offline install command shape: `venv` plus `pip install --no-index
  --no-deps`, `shell=False`, no arbitrary command input
- systemd ExecStart paths now reference
  `/opt/shieldmendai/venv/bin/shieldmendai`
- service-user and ownership plan for `shieldmendai:shieldmendai`,
  `/usr/sbin/nologin`, no home, no sudo
- static temporary-root systemd fixture verification
- runbook order, rollback, and safety documentation updated
- live ownership enforcement resolves users/groups by name, fails closed if
  `shieldmendai` is missing, rejects symlinks/path escapes, and corrects only
  explicit ShieldMendAi allowlisted paths
- runtime apply corrects `/opt/shieldmendai/venv/bin/shieldmendai` to
  `root:shieldmendai 0750`
- package apply enforces the complete ownership plan, including config
  readability without service writability, writable state/log/run directories,
  root-owned systemd units, and runtime traversal directories
- temporary-root fixtures remain isolated, avoid host chown, and include an
  offline runtime CLI fixture for static systemd verification

## Safety Status

Repairs and notifications remain disabled. No public IP address or private
server detail is tracked. The prohibited private source path was not accessed
or used. Rollback remains manifest-owned and preserves modified or unknown
files, unrelated `/root/shieldmend_demo.sh`, and service-user removal as a
separate explicit operator action.

## Resume

Use [Phase 8 canary runbook](PHASE8_CANARY_RUNBOOK.md). The safe live resume
sequence is: verify server identity, verify branch/commit, build a local wheel,
record checksum, preview service-user/ownership, create the service
user/group through reviewed commands, preview/apply offline runtime install,
verify CLI outside the repository with `PYTHONPATH` unset, preview/apply canary
files, run systemd verification, then reload/start only after validation
succeeds. Runtime and package apply now enforce ownership and modes
automatically; do not run separate recursive chown commands.

## Blockers

None known after the readiness fix. Live deployment remains a separate manual
operator action.
