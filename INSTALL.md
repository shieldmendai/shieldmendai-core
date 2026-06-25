# ShieldMendAi Development Installation

ShieldMendAi is currently a Phase 5 simulation framework. There is no
production installer, systemd service, live monitoring engine, or repair
engine yet.

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
```

These commands only parse, validate, normalize, redact, authorize, plan,
simulate, and read controlled fixtures. They perform no live host, process,
systemd, subprocess, network, notification, or repair operation.

## Run Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Production installation, dedicated service users, protected credential files,
and `shieldmendai-*.service` units are planned for later phases.
