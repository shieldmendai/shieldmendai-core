# ShieldMendAI Backend

Read-only backend foundation for ShieldMendAI wallet scanning and tax-lot planning.

This backend must never request seed phrases, private keys, custody, token approvals, or trading permissions. It supports a basic read-only RPC balance check when a configured Base RPC candidate works, and falls back to safe mock responses when live RPC is unavailable.

## Requirements

- Python 3.10 or newer
- No package installation is required for the current foundation server.

## Environment Variables

Create a local `.env` file outside git when real provider credentials are ready. Do not commit `.env`.

Supported placeholders are documented in `.env.example`:

- `BASE_RPC_URL`
- `BASE_RPC_URLS`
- `BASESCAN_API_KEY`
- `GOPLUS_API_KEY`
- `COINGECKO_API_KEY`
- `COVALENT_API_KEY`
- `MORALIS_API_KEY`
- `SIMPLEHASH_API_KEY`
- `PORT`
- `BETA_ACCESS_ENABLED`
- `BETA_FRIEND_CODE_HASH`
- `BETA_CREATOR_CODE_HASHES`
- `APK_DOWNLOAD_URL`

The server does not expose these values and does not require them to start. `BASE_RPC_URL` and `BASE_RPC_URLS`, when present, are parsed as read-only JSON-RPC candidates. Comma-separated and space-separated candidate lists are supported. Only `http://` and `https://` candidates are used.

`BASESCAN_API_KEY`, `ZEROX_API_KEY`, and `GOPLUS_API_KEY` are reported only as configured or not configured in `/api/status`. They are not used for provider calls, approvals, swaps, or trading.

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
- `GET /api/rpc-diagnostics`
- `POST /api/scan-wallet`
- `POST /api/simulate-sale`
- `POST /api/beta-access/verify`

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

Example beta access verification request:

```bash
curl -s http://127.0.0.1:8787/api/beta-access/verify \
  -H 'Content-Type: application/json' \
  -d '{"code":"example-code"}'
```

## Beta Access Gate

`POST /api/beta-access/verify` checks invite codes server-side. It never requires private keys, seed phrases, wallet approvals, custody, swaps, or trading actions.

Keep real access codes out of git. Do not commit plaintext codes, hashed production codes, or APK URLs unless the URL is intentionally public. The private deployment values belong in `backend/.env`.

Beta access environment variables:

- `BETA_ACCESS_ENABLED=false` keeps the endpoint closed with a plain-English "not open yet" message.
- `BETA_FRIEND_CODE_HASH=` stores a SHA-256 hash for one friend/family/tester code.
- `BETA_CREATOR_CODE_HASHES=` stores comma-separated `sha256Hash:creatorLabel` pairs.
- `APK_DOWNLOAD_URL=` stores the APK URL only when an APK is ready to release behind verified access.

Generate a SHA-256 hash for a code without printing or committing the real code:

```bash
printf '%s' 'replace-with-code' | sha256sum
```

Use only the 64-character hash output. Example shape only:

```ini
BETA_ACCESS_ENABLED=true
BETA_FRIEND_CODE_HASH=64_character_sha256_hash_here
BETA_CREATOR_CODE_HASHES=64_character_sha256_hash_here:Creator Label
APK_DOWNLOAD_URL=
```

After changing `backend/.env` on the VPS, restart the service:

```bash
systemctl restart shieldmendai-backend
```

If `APK_DOWNLOAD_URL` is empty, a valid code returns access approved while clearly saying the APK download is not available yet.

## Current Status

- Backend: live when the local service is running
- Wallet scan: `live-basic` only when at least one configured RPC candidate answers `eth_chainId`; otherwise mock
- Tax engine: mock
- Custody: false
- Seed phrase required: false
- Private key required: false
- Wallet approval required: false

## Live-Basic Mode

`live-basic` proves that the backend can reach a read-only EVM RPC endpoint and read a public wallet's native balance. It calls:

- `eth_chainId`
- `eth_getBalance`

The scan response includes the wallet address, chain ID, native balance in wei and ETH, and security flags confirming read-only operation.

This is not a full wallet scanner yet. Token balances, token lots, transaction history, realized gains, cost basis, and tax lots still require transaction history adapters and a real cost-basis/tax engine. Until those are built, the tax engine remains mock.

## RPC Diagnostics

`GET /api/rpc-diagnostics` tests configured read-only RPC candidates with `eth_chainId`. It returns candidate indexes, success flags, chain ID for a working candidate, and sanitized error types. It must not return full RPC URLs, API keys, `.env` values, request paths, or secret-bearing hostnames.

Never add private keys, seed phrases, custody credentials, wallet approvals, trading keys, or swap/trading actions to this backend. The backend must remain read-only.

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
