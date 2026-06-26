# ShieldMendAi Security Boundaries

## Trust Boundaries

- `/root/newbasebot` is a private, stopped, read-only discovery source.
- `/root/ShieldMendAi` is the only public development workspace.
- The official remote is
  `https://github.com/shieldmendai/shieldmendai-core.git`.
- Future dedicated-server installation is a separate, explicitly approved
  operation.

## Never Extract or Publish

- private keys, seed phrases, wallets, wallet history, or credentials;
- Telegram tokens or private chat identifiers;
- API keys or credential-bearing RPC URLs;
- `.env` contents or other credential files;
- trading strategies, buy/sell logic, scoring, or discovery behavior;
- positions, transaction history, PnL, deny lists, or quarantine lists;
- private logs, reports, state, backups, databases, shell history, or user data.

## Discovery Method

Phase 1 used file metadata, hashes, syntax structure, capability classification,
and redacted systemd directive summaries. Private logs, reports, state,
backups, databases, wallet data, configuration values, and strategy modules
were excluded from content review. No private source file was copied.

## Sanitized Security Findings

| Sanitized path | Category | Remediation status |
|---|---|---|
| private source root and configuration files | credential and environment material | Excluded; values not opened or copied |
| private Telegram bridge module | token and private destination handling | Concept only; future notifier requires protected secret references |
| private route/self-healer modules | wallet and credential-bearing RPC dependencies | Excluded from extraction; generic health interfaces will be rewritten |
| private doctor and guardian modules | mutable production service and state actions | Concept only; replace with configured allowlists and dry-run defaults |
| private reports, logs, state, backup, database, and cache trees | operational and potentially identifying data | Excluded entirely |
| private trading, scoring, route, position, deny-list, and quarantine modules | proprietary trading behavior and wallet-private data | Excluded entirely |
| reviewed legacy unit definitions | hardcoded private paths, privileged execution, and legacy names | Do not reuse; create independent least-privilege templates later |

## Public Repository Controls

- `.gitignore` excludes credential, wallet, runtime, report, state, backup,
  database, private configuration, environment, cache, and build artifacts.
- Safe examples such as `.env.example` remain trackable.
- Public scans report file paths and categories, never matched secret values.
- Before every push, inspect tracked files, staged diff, repository status,
  remote URL, and secret-scan results.
- Incident and notification schemas must redact URLs, headers, environment
  values, file contents, command output, and identifiers that may be private.

## Host Controls for Later Phases

- least-privilege service account;
- isolated installation and state directories;
- explicit target and repair allowlists;
- no arbitrary shell commands;
- dry-run before live actions;
- bounded retries, cooldowns, circuit breakers, and post-repair verification;
- secret files readable only by the service identity;
- no access to unrelated trading directories or wallet material.

## Phase 3 Enforcement

- Configuration parsing is local and does not resolve environment variables.
- `dry_run` must be true.
- Direct credential values, authenticated URLs, unrestricted shell command
  strings, private-source paths, and legacy private unit names are rejected.
- The planner and simulation coordinator perform no subprocess, socket, HTTP,
  DNS, process, systemd, notification, vulnerability-scan, or repair action.
- Every registered Phase 3 adapter reports production access unavailable.
- Scenario validation rejects credential-like values, command strings, unknown
  targets, duplicate IDs, adapter mismatches, unsupported states, invalid
  timestamps, and negative durations.
- Fixture paths must remain inside an explicit fixture or temporary root;
  traversal, absolute target paths, arbitrary server roots, and symlink escapes
  are rejected.
- Display output recursively redacts secret-like fields and credential
  references.
- The example uses reserved `.invalid` domains and placeholder environment
  variable names only.
- Tests mock or prohibit live operation and action boundaries.

## Phase 4 Enforcement

- Every repair request is denied unless exact target, adapter, action, and
  target/action allowlists and every applicable safety gate pass.
- Empty allowlists deny; wildcard, duplicate, contradictory, unknown, or
  ambiguous policy entries are rejected.
- Approval records use sanitized references and reject mismatches, expiration,
  revocation, future issue times, and consumed one-time approvals.
- Every permitted simulation requires verification planning. Future
  state-changing actions require rollback planning.
- The repair executor accepts only authorized, unexpired, simulation-only
  plans and returns deterministic records.
- No service, file, permission, ownership, deployment, code, process, network,
  notification, repository, or dedicated-server mutation is implemented.

## Phase 5 Enforcement

- Recovery accepts only authorized Phase 4 simulation plans and supplied
  fictional outcomes.
- Retry, verification, rollback, half-open, cooldown, and backoff behavior is
  finite and deterministic; no sleep, recursive execution, or unbounded queue
  exists.
- Exact plan, request/action, and attempt identifiers prevent replay.
- Versioned recovery state rejects unknown fields, invalid states, impossible
  combinations, production mode, and credential-like material.
- Failure windows store only typed timestamps and identifiers, never logs or
  full evidence.
- No live repair, verification, rollback, observer, service, process, file,
  permission, deployment, network, notification, or repository operation is
  implemented.

## Phase 6 Enforcement

- Incident records accept only typed sanitized fields, structured evidence
  references, known schema versions, chronological unique events, and valid
  checksums.
- Incident stores require an explicit existing temporary root and reject
  traversal, unsafe absolute roots, and symlink escapes.
- Retention defaults to preview and can remove only eligible generated
  fixtures under a validated temporary root.
- Telegram, email, SMS, and webhook providers are deterministic simulations
  with production delivery, network use, and secret resolution unavailable.
- Notification configuration accepts environment-variable names and sanitized
  destination references only; it never reads environment values.
- Templates use a fixed variable allowlist and cannot execute code, import
  files, expand environment variables, or render complete evidence.
- Routing, duplicate suppression, cooldowns, and attempt budgets use supplied
  timestamps and exact matching. No sleep or background loop exists.
- No real message, provider contact, external upload, production incident
  directory, production deletion, monitoring, repair, recovery, or deployment
  is implemented.

## Phase 7 Enforcement

- Installation roots must be existing explicit temporary subdirectories and
  cannot be production roots, repository directories, traversal paths, or
  symlink escapes.
- Production filesystem paths are models mapped under the sandbox.
- User/group creation, ownership and permission changes, package installation,
  systemd installation/control, shell commands, and network access are absent.
- Uninstallation defaults to preview, requires explicit fixture-removal
  authorization, and removes only unmodified manifest-recorded files.
- Linux targets use exact IDs, identities, adapters, and read paths. Wildcards,
  implicit discovery, non-local targets, and mutation-enabled targets are
  denied.
- Production observers are disabled. Fixture observers are read-only and run
  once per invocation without process enumeration, systemd contact, sockets,
  HTTP, TCP, sleep, repair, or notification delivery.
- Incident and observation records remain sanitized, checksummed, and confined
  to the validated temporary sandbox.

## Phase 8 Enforcement

- The original Phase 8 package was not live-ready because actual file modes
  and runtime installation were incomplete. The readiness audit caught those
  blockers before live installation.
- The dedicated canary configuration rejects unknown fields, wildcards,
  non-local targets, mutation-enabled targets, network targets, process
  enumeration, automatic discovery, repairs, and notification delivery.
- Host validation requires the expected hostname or an explicit reviewed
  canary identity; public IP addresses are rejected from tracked configuration.
- Preview is the default. Installation and rollback apply commands require
  `--apply`; reviewed live-root use additionally requires `--live-reviewed`.
- Installation refuses repository paths, prohibited private paths, traversal,
  symlink escapes, and conflicting existing files.
- Installation enforces actual modes under the explicit temporary root:
  launchers `0750`, configuration `0640`, manifest/audit `0640`, and systemd
  units `0644`. The manifest records actual resulting file modes.
- Offline runtime installation accepts only a local ShieldMendAi wheel, checks
  expected name, expected version, checksum, traversal, symlink escapes, and
  conflicting runtimes, and runs fixed `venv` and `pip install --no-index
  --no-deps` commands with `shell=False`.
- The service-user plan is `shieldmendai:shieldmendai`,
  `/usr/sbin/nologin`, no home, no sudo, and no root runtime. `/opt` and
  `/etc` are root-owned and service-readable; state, incident, demo, log, and
  runtime directories are service-owned.
- The manifest is checksummed. Rollback stops/disables canary units first,
  removes only manifest-owned unchanged files, preserves modified or unknown
  files, preserves unrelated `/root/shieldmend_demo.sh`, and leaves service
  user removal as a separate explicit operator action.
- Hardened units use a non-root service user, empty capabilities, strict
  filesystem protection, exact read/write paths, private networking, and no
  repair or notification command. ExecStart references
  `/opt/shieldmendai/venv/bin/shieldmendai`.
- The observer reads one ShieldMendAi-owned JSON health artifact per invocation
  and records sanitized local incidents only. It does not restart, kill, start,
  rewrite, invoke `os.system`, call HTTP, open sockets, send Telegram, resolve
  environment secrets, enumerate unrestricted `/proc`, or inspect unrelated
  services.
