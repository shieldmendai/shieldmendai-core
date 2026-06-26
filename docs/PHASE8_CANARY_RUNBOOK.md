# Phase 8 Dedicated Canary Runbook

Status: readiness fix prepared only. No live deployment has occurred, the
dedicated server was not contacted, and no installation was performed during
this Codex run.

The original Phase 8 package was not live-ready: the readiness audit found that
generated launchers and configuration files did not receive their declared
actual modes, the package was not importable outside the repository, the
launcher was not executable, and systemd referenced unavailable commands. The
audit safely caught these blockers before live installation.

Repairs and notifications remain disabled.

## Required Order

1. Verify server identity.
2. Verify branch and commit.
3. Build the wheel locally.
4. Record wheel checksum.
5. Preview service-user creation and filesystem ownership plan.
6. Operator creates service user/group.
7. Preview runtime installation.
8. Apply isolated offline runtime installation.
9. Verify CLI outside the repository with `PYTHONPATH` unset.
10. Preview canary file installation.
11. Apply canary file installation.
12. Apply validated ownership and modes.
13. Run systemd-analyze verification.
14. Reload systemd only after all verification succeeds.
15. Start the harmless demo service.
16. Run one manual read-only observation.
17. Enable timers only after manual observation succeeds.

## Build The Wheel

Run in the reviewed repository checkout:

```bash
git status --short --branch
git rev-parse HEAD
python3 -m pip wheel . --no-deps --no-build-isolation -w dist
python3 - <<'PY'
from pathlib import Path
import hashlib
wheel = next(Path("dist").glob("shieldmendai-*.whl"))
print(wheel)
print(hashlib.sha256(wheel.read_bytes()).hexdigest())
PY
```

Transfer only the reviewed wheel by an operator-approved method.

## Service User And Ownership

Preview from the reviewed repository checkout before the runtime exists:

```bash
PYTHONPATH=src python3 -m shieldmendai show-canary-service-user-plan
```

Reviewed service identity commands:

```bash
sudo groupadd --system shieldmendai
sudo useradd --system --gid shieldmendai --shell /usr/sbin/nologin --no-create-home shieldmendai
getent passwd shieldmendai
getent group shieldmendai
sudo -l -U shieldmendai
```

Reviewed ownership and modes:

```bash
sudo install -d -o root -g shieldmendai -m 0750 /opt/shieldmendai
sudo install -d -o root -g shieldmendai -m 0750 /etc/shieldmendai
sudo install -d -o shieldmendai -g shieldmendai -m 0750 /var/lib/shieldmendai
sudo install -d -o shieldmendai -g shieldmendai -m 0750 /var/lib/shieldmendai/incidents
sudo install -d -o shieldmendai -g shieldmendai -m 0750 /var/lib/shieldmendai/demo
sudo install -d -o shieldmendai -g shieldmendai -m 0750 /var/log/shieldmendai
sudo install -d -o shieldmendai -g shieldmendai -m 0750 /run/shieldmendai
sudo chown root:shieldmendai /etc/shieldmendai/*.yaml
sudo chmod 0640 /etc/shieldmendai/*.yaml
sudo chown root:root /etc/systemd/system/shieldmendai-*.service /etc/systemd/system/shieldmendai-*.timer
sudo chmod 0644 /etc/systemd/system/shieldmendai-*.service /etc/systemd/system/shieldmendai-*.timer
```

`/opt/shieldmendai` and `/etc/shieldmendai` are not writable by the service.
State, incident, demo, log, and runtime directories are owned by
`shieldmendai:shieldmendai`.

## Offline Runtime

The runtime installer validates an exact local ShieldMendAi wheel path, package
name, package version, checksum, path traversal, symlink escapes, and existing
runtime markers. It uses fixed argument lists, `shell=False`, `--no-index`, and
`--no-deps`; it performs no dependency resolution and has no public package
download path.

Preview:

```bash
/path/to/current/shieldmendai canary-runtime-install-preview /absolute/path/to/shieldmendai-0.4.0-py3-none-any.whl --runtime-path /opt/shieldmendai/venv --expected-version 0.4.0 --expected-sha256 WHEEL_SHA256 --live-reviewed
```

Apply:

```bash
/path/to/current/shieldmendai canary-runtime-install-apply /absolute/path/to/shieldmendai-0.4.0-py3-none-any.whl --runtime-path /opt/shieldmendai/venv --expected-version 0.4.0 --expected-sha256 WHEEL_SHA256 --apply --live-reviewed
PYTHONPATH= /opt/shieldmendai/venv/bin/python -c 'import shieldmendai; print(shieldmendai.__version__)'
PYTHONPATH= /opt/shieldmendai/venv/bin/shieldmendai --help
```

## Canary Files

Preview:

```bash
/opt/shieldmendai/venv/bin/shieldmendai inspect-canary-config /absolute/path/to/dedicated-canary.yaml
/opt/shieldmendai/venv/bin/shieldmendai render-canary-systemd-units
/opt/shieldmendai/venv/bin/shieldmendai canary-install-preview / --config-path /absolute/path/to/dedicated-canary.yaml --actual-hostname shieldmendai --live-reviewed
```

Apply:

```bash
/opt/shieldmendai/venv/bin/shieldmendai canary-install-apply / --config-path /absolute/path/to/dedicated-canary.yaml --actual-hostname shieldmendai --apply --live-reviewed
```

Expected actual modes:

- launchers/programs: `0750`
- configuration files: `0640`
- installation manifest and audit: `0640`
- systemd units: `0644`
- directories created by the installer model: restrictive, normally `0750`

The manifest records the actual resulting file mode.

## Systemd Verification

The generated service units execute:

```text
/opt/shieldmendai/venv/bin/shieldmendai
```

Use a temporary-root fixture before live activation:

```bash
/opt/shieldmendai/venv/bin/shieldmendai verify-canary-systemd-fixture /tmp/shieldmendai-complete-fixture
```

Then verify the live unit files after file installation and ownership/mode
application:

```bash
systemd-analyze verify /etc/systemd/system/shieldmendai-demo.service
systemd-analyze verify /etc/systemd/system/shieldmendai-observer.service
systemd-analyze verify /etc/systemd/system/shieldmendai-observer.timer
systemd-analyze verify /etc/systemd/system/shieldmendai-incident-maintenance.service
systemd-analyze verify /etc/systemd/system/shieldmendai-incident-maintenance.timer
```

Only after every verification succeeds:

```bash
sudo systemctl daemon-reload
sudo systemctl start shieldmendai-demo.service
/opt/shieldmendai/venv/bin/shieldmendai canary-observe / --config-path /etc/shieldmendai/dedicated-canary.yaml --live-reviewed
sudo systemctl enable --now shieldmendai-observer.timer
sudo systemctl enable --now shieldmendai-incident-maintenance.timer
```

Do not enable repair or notification capabilities.

## Rollback

Stop and disable canary units before removing files:

```bash
sudo systemctl disable --now shieldmendai-observer.timer shieldmendai-incident-maintenance.timer
sudo systemctl stop shieldmendai-observer.service shieldmendai-incident-maintenance.service shieldmendai-demo.service
/opt/shieldmendai/venv/bin/shieldmendai canary-rollback-preview / --live-reviewed
/opt/shieldmendai/venv/bin/shieldmendai canary-rollback-apply / --apply --live-reviewed
systemctl list-unit-files 'shieldmendai-*'
```

Rollback removes only manifest-owned runtime and installation files whose
checksums still match. Modified or unknown files are preserved, unrelated
`/root/shieldmend_demo.sh` is preserved, and incident history is preserved
unless an explicit operator flag is added in a future reviewed tool.

Removing the service user is a separate explicit operator action. Never delete
an unknown user or group.
