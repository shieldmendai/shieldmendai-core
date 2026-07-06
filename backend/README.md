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
- `PORT`

The current server does not expose these values and does not require them to start.

## Run Locally

From the repo root:

```bash
python3 backend/server.py
```

Optional host and port:

```bash
SHIELDMEND_HOST=127.0.0.1 PORT=8787 python3 backend/server.py
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

## Current Status

- Backend: live when the local service is running
- Wallet scan: mock
- Tax engine: mock
- Custody: false
- Seed phrase required: false
- Private key required: false
- Wallet approval required: false

Do not claim live wallet scanning until real read-only RPC/API providers are configured and tested.

## Systemd Service

The deployed service name is `shieldmendai-backend.service`. It binds to `127.0.0.1:8787` by default and does not include secrets in the unit file.

The active VPS unit should use this shape:

```ini
[Unit]
Description=ShieldMendAI read-only backend
After=network.target

[Service]
Type=simple
WorkingDirectory=/root/ShieldMendAi
EnvironmentFile=-/root/ShieldMendAi/backend/.env
Environment=SHIELDMEND_HOST=127.0.0.1
Environment=PORT=8787
ExecStart=/usr/bin/python3 /root/ShieldMendAi/backend/server.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

The dash before `EnvironmentFile` lets the service start even when `backend/.env` does not exist. Do not commit `backend/.env`.

Install or refresh the service on the VPS:

```bash
systemctl daemon-reload
systemctl enable shieldmendai-backend
systemctl restart shieldmendai-backend
```

Check status:

```bash
systemctl status shieldmendai-backend --no-pager
curl -s http://127.0.0.1:8787/health
curl -s http://127.0.0.1:8787/api/status
```

Stop or restart:

```bash
systemctl stop shieldmendai-backend
systemctl restart shieldmendai-backend
```

If real provider variables are needed later, keep them in a local environment file that is not committed and update the service carefully. Do not store private keys, seed phrases, trading wallet credentials, or token approval credentials in the backend environment.
