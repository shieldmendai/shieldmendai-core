# ShieldMendAI Backend

Read-only backend foundation for ShieldMendAI wallet scanning and tax-lot planning.

This backend must never request seed phrases, private keys, custody, token approvals, or trading permissions. The initial implementation returns safe mock wallet and tax-planning responses until a read-only RPC/data provider adapter and tax calculation engine are implemented.

## Requirements

- Python 3.10 or newer
- No package installation is required for the current foundation server.

## Environment Variables

Create a local `.env` file outside git when real provider credentials are ready. Do not commit `.env`.

Supported placeholders are documented in `.env.example`:

- `BASE_RPC_URL`
- `BASESCAN_API_KEY`
- `COINGECKO_API_KEY`
- `COVALENT_API_KEY`
- `MORALIS_API_KEY`
- `SIMPLEHASH_API_KEY`

The current server does not expose these values and does not require them to start.

## Run Locally

From the repo root:

```bash
python3 backend/server.py
```

Optional host and port:

```bash
SHIELDMEND_HOST=127.0.0.1 SHIELDMEND_PORT=8787 python3 backend/server.py
```

## Endpoints

- `GET /health`
- `GET /api/status`
- `POST /api/scan-wallet`
- `POST /api/simulate-sale`

Example scan request:

```bash
curl -s http://127.0.0.1:8787/api/scan-wallet \
  -H 'Content-Type: application/json' \
  -d '{"wallet":"0x7a000000000000000000000000000000000091F"}'
```

Example simulation request:

```bash
curl -s http://127.0.0.1:8787/api/simulate-sale \
  -H 'Content-Type: application/json' \
  -d '{"wallet":"0x7a000000000000000000000000000000000091F","token":"ETH","amount":1.25,"salePriceUsd":2500}'
```

## Systemd Later

When deploying, create a dedicated unprivileged service user and point systemd at the repo path. Keep secrets in a root-readable environment file that is not committed.

Example outline:

```ini
[Unit]
Description=ShieldMendAI read-only backend
After=network.target

[Service]
Type=simple
WorkingDirectory=/root/ShieldMendAi
EnvironmentFile=/etc/shieldmendai/backend.env
ExecStart=/usr/bin/python3 /root/ShieldMendAi/backend/server.py
Restart=on-failure
User=shieldmend

[Install]
WantedBy=multi-user.target
```

Do not store private keys, seed phrases, trading wallet credentials, or token approval credentials in the backend environment.
