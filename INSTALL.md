# ShieldMendAi Development Installation

ShieldMendAi is currently a Phase 8 read-only dedicated canary deployment
package. The package has been prepared for manual operator execution; deployment
has not been applied.

## Requirements

- Python 3.10 or newer
- `pip`
- An isolated virtual environment

## Editable Installation

```bash
git clone https://github.com/shieldmendai/shieldmendai-core.git
cd shieldmendai-core
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

## Validate the Example

```bash
shieldmendai validate-config examples/shieldmendai.example.yaml
shieldmendai plan examples/shieldmendai.example.yaml
shieldmendai show-config examples/shieldmendai.example.yaml
shieldmendai list-adapters
shieldmendai inspect-scenario examples/scenarios/phase3-example.yaml
shieldmendai simulate examples/simulation-config.yaml examples/scenarios/phase3-example.yaml
shieldmendai list-repair-actions
shieldmendai inspect-repair-policy examples/repair/policy.yaml
shieldmendai authorize-repair examples/repair/config.yaml examples/repair/request.yaml examples/repair/policy.yaml
shieldmendai plan-repair examples/repair/config.yaml examples/repair/request.yaml examples/repair/policy.yaml
shieldmendai simulate-repair examples/repair/config.yaml examples/repair/request.yaml examples/repair/policy.yaml examples/repair/scenarios/success.yaml
shieldmendai inspect-recovery-policy examples/recovery/policy.yaml
shieldmendai calculate-backoff examples/recovery/policy.yaml 2
shieldmendai simulate-recovery examples/repair/config.yaml examples/repair/request.yaml examples/repair/policy.yaml examples/recovery/policy.yaml examples/recovery/scenarios/first-success.yaml
shieldmendai list-notifiers
shieldmendai inspect-notification-policy examples/notifications/policy.yaml
shieldmendai inspect-incident examples/incidents/incident-low.json
shieldmendai render-notification examples/incidents/incident-low.json examples/notifications/policy.yaml examples/notifications/template.yaml
shieldmendai simulate-notification examples/incidents/incident-low.json examples/notifications/policy.yaml examples/notifications/scenario.yaml --template-path examples/notifications/template.yaml
shieldmendai inspect-installation-plan examples/installation/plan.yaml
shieldmendai plan-install examples/installation/plan.yaml
shieldmendai render-systemd-units examples/installation/plan.yaml
shieldmendai inspect-pilot-policy examples/pilot/policy.yaml
shieldmendai list-linux-observers
shieldmendai inspect-canary-config examples/canary/dedicated-canary.yaml
shieldmendai render-canary-systemd-units
```

These commands only parse, validate, normalize, redact, authorize, plan,
simulate, and read or write controlled temporary fixtures. They perform no
live host, process, systemd, subprocess, network, real notification, repair,
production retention, or deployment operation. Notification references are
validated but never resolved.

## Run Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

`simulate-install` and `simulate-uninstall` require an explicit existing
temporary subdirectory. They never write to the modeled production paths.
Pilot simulation requires caller-created fictional fixtures beneath the same
temporary root. See
[Phase 7 installation and pilot](docs/INSTALLATION_AND_LINUX_PILOT.md).

## Dedicated Canary Package

See [Phase 8 canary runbook](docs/PHASE8_CANARY_RUNBOOK.md). The runbook keeps
swap creation and Ubuntu package installation as separate operator-reviewed
commands. The ShieldMendAi package never installs OS packages, opens firewall
ports, copies secrets, enables repairs, or enables notifications.

All mutating canary CLI commands require `--apply`; preview is the default.
The future live service identity is `shieldmendai:shieldmendai` with
`/usr/sbin/nologin`, no interactive home, no sudo access, and no root runtime.
