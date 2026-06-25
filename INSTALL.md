# ShieldMendAi Development Installation

ShieldMendAi is currently a Phase 3 simulation framework. There is no
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
```

These commands only parse, validate, normalize, redact, plan, simulate, and
read controlled fixtures. They perform no live host, process, systemd,
subprocess, or network operation.

## Run Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Production installation, dedicated service users, protected credential files,
and `shieldmendai-*.service` units are planned for later phases.
