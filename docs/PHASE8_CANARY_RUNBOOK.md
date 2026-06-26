# Phase 8 Dedicated Canary Runbook

Status: deployment package prepared only. Deployment has not been applied.

This runbook is for the manually verified dedicated server:

- Hostname: `shieldmendai`
- Ubuntu 24.04.3 LTS
- Python 3.12.3
- Git 2.43.0

No public IP address is recorded here. Do not use `/root/shieldmend_demo.sh`;
it is unrelated and must remain untouched. Do not access `/root/newbasebot`.

## Prerequisites

Review and run these commands manually on the dedicated server only if the
operator approves them. They are intentionally separate from the installer.

```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
swapon --show
free -h
```

```bash
sudo apt update
sudo apt install --no-install-recommends python3 python3-venv python3-pip git
python3 --version
python3 -m pip --version
git --version
```

## Build And Transfer

Build the wheel on a trusted workstation or checked-out repository:

```bash
python3 -m pip wheel . --no-deps --no-build-isolation -w dist
python3 -m json.tool extraction_manifest.json >/dev/null
```

Transfer the repository checkout or the locally built wheel to the dedicated
server by an operator-reviewed method. Do not fetch Python dependencies from
the public internet during installation; use `--no-deps`.

## Manual Commands

Preview is the default behavior. Apply operations require `--apply`.

```bash
shieldmendai inspect-canary-config examples/canary/dedicated-canary.yaml
shieldmendai render-canary-systemd-units
shieldmendai canary-install-preview /tmp/shieldmendai-canary-root --config-path examples/canary/dedicated-canary.yaml --actual-hostname shieldmendai
shieldmendai canary-install-apply /tmp/shieldmendai-canary-root --config-path examples/canary/dedicated-canary.yaml --actual-hostname shieldmendai --apply
shieldmendai canary-observe /tmp/shieldmendai-canary-root --config-path examples/canary/dedicated-canary.yaml
shieldmendai canary-rollback-preview /tmp/shieldmendai-canary-root
shieldmendai canary-rollback-apply /tmp/shieldmendai-canary-root --apply
```

For the verified dedicated server only, the equivalent reviewed live-root
commands use `/` and must include `--live-reviewed`:

```bash
shieldmendai canary-install-preview / --config-path /etc/shieldmendai/dedicated-canary.yaml --actual-hostname shieldmendai --live-reviewed
shieldmendai canary-install-apply / --config-path /etc/shieldmendai/dedicated-canary.yaml --actual-hostname shieldmendai --apply --live-reviewed
shieldmendai canary-observe / --config-path /etc/shieldmendai/dedicated-canary.yaml --live-reviewed
shieldmendai canary-rollback-preview / --live-reviewed
shieldmendai canary-rollback-apply / --apply --live-reviewed
```

The future live layout is:

- `/opt/shieldmendai`
- `/etc/shieldmendai`
- `/var/lib/shieldmendai`
- `/var/lib/shieldmendai/incidents`
- `/var/log/shieldmendai`
- `/run/shieldmendai`
- `/etc/systemd/system/shieldmendai-observer.service`
- `/etc/systemd/system/shieldmendai-observer.timer`
- `/etc/systemd/system/shieldmendai-incident-maintenance.service`
- `/etc/systemd/system/shieldmendai-incident-maintenance.timer`
- `/etc/systemd/system/shieldmendai-demo.service`

The modeled service identity is `shieldmendai:shieldmendai`, shell
`/usr/sbin/nologin`, no interactive home directory, no sudo access, and no root
runtime.

## Canary Proof

The demo target is a local JSON health artifact at
`/var/lib/shieldmendai/demo/health.json`. It contains no trading logic, wallet
logic, credentials, tokens, customer data, privileged action, or network port.

Proof sequence:

1. Observe healthy JSON and confirm no incident is open.
2. Operator deliberately stops the demo service or removes the health artifact.
3. Run one observer cycle.
4. Confirm a sanitized local incident exists.
5. Confirm ShieldMendAi did not repair, restart, rewrite, or mutate the target.
6. Operator manually restores the demo service or health artifact.
7. Run one observer cycle.
8. Confirm the incident is resolved by verification.

ShieldMendAi does not send notifications, open network connections, inspect
unrelated services, enumerate unrestricted `/proc`, discover targets
automatically, resolve environment secrets, or access `/root/newbasebot`.

## Systemd Notes

The rendered units use `User=shieldmendai`, `Group=shieldmendai`,
`NoNewPrivileges=true`, `PrivateTmp=true`, `PrivateDevices=true`,
`ProtectSystem=strict`, `ProtectHome=true`, kernel and control-group
protections, empty capabilities, `UMask=0077`, `PrivateNetwork=true`,
`IPAddressDeny=any`, exact `ReadOnlyPaths`, and exact `ReadWritePaths`.

`RestrictAddressFamilies=AF_UNIX` is retained so local process service-manager
status observation can be separately reviewed in a future live adapter. Phase 8
does not perform systemd D-Bus calls during this Codex run.

## Rollback

Rollback preview changes nothing. Rollback apply removes only manifest-owned
files whose checksums still match. Modified files block removal. Unknown files
are preserved.
