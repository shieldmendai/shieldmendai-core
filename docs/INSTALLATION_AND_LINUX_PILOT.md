# Phase 7 Installation Sandbox and Linux Pilot

Phase 7 creates an installation-ready safety boundary without installing
ShieldMendAi on the host. It also provides one explicit, local-only,
fixture-backed Linux observation cycle.

## Installation architecture

The installation plan models the future Linux layout:

```text
/opt/shieldmendai
/etc/shieldmendai
/var/lib/shieldmendai
/var/lib/shieldmendai/incidents
/var/log/shieldmendai
/run/shieldmendai
/etc/systemd/system/shieldmendai-*.service
/etc/systemd/system/shieldmendai-*.timer
```

Every path is mapped beneath an explicitly supplied, existing operating-system
temporary directory. Production roots, the temporary root itself, repository
directories, traversal, and symlink escape are rejected.

The simulated installer writes a public package-entrypoint placeholder, a safe
bootstrap configuration, four systemd templates, and a versioned checksummed
installation manifest. Repeating the same installation is idempotent. Existing
content that differs from the manifest is a conflict.

The service-user plan uses user and group `shieldmendai`, no interactive shell,
no home directory, no sudo, and no root execution. Ownership and modes are
metadata only. The service may write only modeled ShieldMendAi state, incident,
log, and runtime paths. Future adapters must request and review any additional
scope.

## Uninstallation

Uninstallation is preview-only by default. Fixture removal requires
`--remove-generated-fixtures`. It verifies the installation ID and manifest
checksum, removes only recorded unmodified files, removes only empty
installer-created directories, preserves unknown files, rejects symlinks and
traversal, and reports modified-file conflicts. It never claims that a
production installation was removed.

## Bootstrap configuration and systemd templates

Bootstrap configuration is local-only and read-only. Observation is enabled;
repairs, notification delivery, network access, automatic discovery, and
secret resolution are disabled. Targets are exact IDs with no wildcards.

Templates are previews only. They use the `shieldmendai` identity,
`NoNewPrivileges=true`, restrictive filesystem and capability controls,
private temporary storage, `UMask=0077`, direct CLI references, no shell
wrapper, no inline secret, no repair command, no notification delivery, and no
network dependency.

## Exact target allowlist and pilot policy

Each target declares an exact target ID, application ID, adapter type,
observation type, expected identity, fixture reference, exact allowed read
paths, denied paths, locality, read-only status, enabled status, severity,
interval, and incident category. Wildcards, duplicates, unknown targets,
non-local targets, and mutation-enabled targets are denied.

The Phase 7 policy requires `local_only`, `read_only`, `sandbox_only`, and
`review_required`. Repairs, notifications, networking, process enumeration,
and systemd access are disabled. Unknown policy fields are rejected.

Fixture adapters cover service state, timer state, expected process presence,
executable presence, file existence/readability/checksum, and JSON/YAML/TOML
validity. HTTP and TCP capabilities are declared but denied because networking
is disabled. Production adapter objects exist only to reject execution.

The controller runs once per CLI invocation and never sleeps or loops. It
normalizes findings, emits sanitized observation audits, creates checksummed
Phase 6 incident records for unhealthy findings, and resolves an open incident
after a later healthy fixture recheck.

## CLI

```text
shieldmendai inspect-installation-plan PLAN_PATH
shieldmendai plan-install CONFIG_PATH
shieldmendai simulate-install CONFIG_PATH SANDBOX_ROOT
shieldmendai inspect-installation SANDBOX_ROOT
shieldmendai preview-uninstall SANDBOX_ROOT
shieldmendai simulate-uninstall SANDBOX_ROOT --remove-generated-fixtures
shieldmendai render-systemd-units CONFIG_PATH
shieldmendai inspect-pilot-policy POLICY_PATH
shieldmendai list-linux-observers
shieldmendai simulate-linux-pilot CONFIG_PATH POLICY_PATH SCENARIO_PATH SANDBOX_ROOT
```

Exit codes are `0` success, `1` invalid input, `2` target/adapter denied, `3`
unhealthy finding, `5` installation integrity failure, `6` unsafe sandbox,
`7` uninstall/install conflict, and `8` production or live pilot request
denied. Existing command exit codes remain unchanged.

## Safety statement

No real installation occurred. No Linux user or group was created. No
ownership or permission was changed. No systemd unit was installed, enabled,
reloaded, or started. No live server, process table, systemd manager, HTTP
endpoint, TCP port, disk, memory, or load source was observed. No repair,
restart, notification, package installation, deployment, or network connection
occurred. No production path or customer system was modified.

## Exact Phase 8 task

Deploy ShieldMendAi to its dedicated test server in a strictly read-only canary
configuration. Verify server identity; create the dedicated service user;
perform a controlled checksummed installation; create the real local layout;
install the observer service and timer; allowlist only ShieldMendAi-owned test
targets; persist local incidents; keep automatic repairs, restarts, production
notifications, and customer deployment disabled; and verify rollback and
uninstallation.
