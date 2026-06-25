# Phase 3 Simulation

Phase 3 implements deterministic observation simulations and controlled
fixture-file checks. It does not monitor live services, processes, endpoints,
commands, or operating-system state.

## Commands

```bash
shieldmendai list-adapters
shieldmendai inspect-scenario examples/scenarios/phase3-example.yaml
shieldmendai simulate \
  examples/simulation-config.yaml \
  examples/scenarios/phase3-example.yaml
```

Every simulation run is labeled:

```text
SIMULATION ONLY — NO LIVE SYSTEM ACCESS
```

`inspect-scenario` validates and summarizes target IDs, adapter types, states,
timestamps, durations, and fixture-root presence. It does not dispatch an
adapter or reveal scenario data values.

## Scenario Format

A scenario contains a schema version, ISO-8601 observation timestamp, optional
fixture root, and a non-empty target list. Every target declares:

- `target_id`, which must exist in the validated main configuration;
- `adapter_type`, which must match that configured target;
- a supported deterministic `state`;
- a non-negative `duration_ms`;
- optional non-sensitive structured `data`.

Duplicate IDs, unknown states, mismatched adapters, command strings,
credential-like fields, authenticated URLs, invalid timestamps, and negative
durations are rejected.

## Registered Adapters

Simulation-only adapters are registered for:

```text
systemd_service  systemd_timer  process  pid_file  http  tcp
executable_check  file  json_file  yaml_file  toml_file
```

Each capability declaration reports `supports_simulation: true` and
`production_available: false`. The registry uses fixed in-process
implementations. It does not dynamically import plugins, evaluate code, run
shell commands, or load customer extensions.

## Fixture Checks

File checks may read only paths confined beneath an explicitly supplied
fixture or temporary root. Absolute target paths, path traversal, symlink
escapes, arbitrary server roots, and the prohibited private source root are
rejected.

Supported read-only checks are existence, modification-time freshness,
permission-mode bits, SHA-256 comparison, JSON parsing, safe YAML parsing, and
TOML parsing. Findings include metadata only; full file contents are not
included. Observations do not modify permissions, ownership, timestamps, or
contents.

## Findings and Exit Codes

Findings contain target and adapter identity, timestamp, status, severity,
category, confidence, sanitized evidence, expected and observed states,
duration, error classification, retry recommendation, manual-review flag,
simulation flag, and adapter version.

Stable exit behavior:

- `0`: valid simulation and all observed targets healthy;
- `1`: invalid CLI input, configuration, or scenario;
- `2`: one or more degraded, unhealthy, unknown, skipped-exception, or
  unsupported simulated findings;
- `3`: observation or adapter execution error;
- `4`: unsupported adapter or unsafe operation rejected.

No result confirms a real vulnerability or real production condition.
