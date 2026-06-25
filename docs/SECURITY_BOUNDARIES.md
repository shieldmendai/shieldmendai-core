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
