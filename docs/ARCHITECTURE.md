# ShieldMendAi Architecture

## Design Principles

ShieldMendAi is a standalone, deny-by-default recovery system. Monitored
targets and permitted repairs come only from user configuration. Source-project
paths and legacy unit names are not defaults, aliases, or implicit targets.

The engine separates observation, policy, execution, verification, and
reporting. A failed observation never directly invokes a shell command.

## Components

1. **Configuration loader** — validates targets, probes, policies, repair
   allowlists, retry budgets, retention, and optional notifier settings.
2. **systemd monitor** — reads configured unit load and active state through a
   constrained adapter.
3. **File-health monitor** — checks configured existence, type, age, size,
   parseability, mode, and ownership expectations without recording contents.
4. **Process-health monitor** — checks configured process identity, liveness,
   age, and duplicate-count constraints.
5. **Command or HTTP adapter** — runs fixed configured probes with timeouts and
   redacted output, or performs bounded HTTP checks with secrets separated from
   logged URLs.
6. **Policy engine** — maps normalized observations to no-op, incident, or an
   explicitly allowlisted repair plan.
7. **Allowlisted repair executor** — supports a small action registry such as
   restart configured unit, create configured directory, restore a validated
   public template, or correct configured mode/ownership. Arbitrary shell
   strings are rejected.
8. **Recovery verifier** — reruns the relevant probes after a repair and
   records success only when configured conditions pass.
9. **Cooldown and retry controller** — enforces retry budgets, exponential
   backoff, cooldowns, circuit breakers, and restart-loop prevention per target.
10. **Incident recorder** — writes structured, redacted events with target IDs,
    observation categories, decisions, actions, and verification outcomes.
11. **Optional Telegram notifier** — sends selected redacted incident summaries
    when enabled; tokens and chat identifiers remain secret configuration.
12. **CLI** — provides configuration validation, status, check, dry-run, repair
    approval, incident inspection, and version commands.
13. **Installer** — installs into an isolated directory with least-privilege
    ownership and `shieldmendai-*` systemd definitions.
14. **Test harness** — supplies fake clocks, filesystems, process tables,
    systemd adapters, HTTP endpoints, and action executors.

## Control Flow

```text
configuration
    -> monitors/probes
    -> normalized observations
    -> policy decision
    -> cooldown/retry authorization
    -> dry-run plan or allowlisted executor
    -> recovery verification
    -> redacted incident
    -> optional notification
```

## Configuration Model

Each target receives a stable public ID and declares:

- monitor adapter and non-secret parameters;
- health thresholds and timeout;
- allowed repair action IDs and constrained arguments;
- verification probes;
- retry count, backoff, cooldown, and circuit-breaker limits;
- incident severity and notification policy.

Secret values are referenced from protected environment or credential files,
not embedded in normal configuration, command lines, incidents, or logs.

## Safety Invariants

- Dry-run is the initial and default deployment mode.
- Unknown targets and actions are denied.
- A repair cannot address a target absent from configuration.
- Commands use argument arrays, fixed executables, timeouts, and no shell.
- File writes use confined paths and atomic replacement where appropriate.
- Backups, if supported later, are bounded, permission-controlled, and never
  imported from the private source.
- Verification is mandatory before reporting recovery.
- Retry exhaustion opens a circuit and requires an explicit policy transition.
- Notifications are optional and cannot change repair decisions.
