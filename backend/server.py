#!/usr/bin/env python3
"""Read-only ShieldMendAI backend foundation.

This server intentionally avoids custody, private keys, seed phrases, approvals,
and trading operations. Initial scan and simulation responses are mock data until
read-only provider adapters and a real tax engine are implemented.
"""

from __future__ import annotations

import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


HOST = os.environ.get("SHIELDMEND_HOST", "127.0.0.1")
PORT = int(os.environ.get("SHIELDMEND_PORT", "8787"))
WALLET_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def provider_configured() -> bool:
    return any(
        os.environ.get(name)
        for name in (
            "BASE_RPC_URL",
            "BASESCAN_API_KEY",
            "COINGECKO_API_KEY",
            "COVALENT_API_KEY",
            "MORALIS_API_KEY",
            "SIMPLEHASH_API_KEY",
        )
    )


def status_payload() -> dict[str, Any]:
    return {
        "backend": "live",
        "walletScan": "mock",
        "taxEngine": "mock",
        "readOnlyProviderConfigured": provider_configured(),
        "custody": False,
        "requiresSeedPhrase": False,
        "requiresPrivateKey": False,
        "requiresWalletApproval": False,
    }


def mock_scan(wallet: str) -> dict[str, Any]:
    return {
        "mode": "mock",
        "wallet": wallet,
        "readOnly": True,
        "message": "Mock scan data. Configure and implement read-only provider adapters before using live wallet data.",
        "tokens": [
            {
                "symbol": "ETH",
                "balance": "2.5000",
                "estimatedValueUsd": 6250.00,
                "lots": [
                    {
                        "acquiredAt": "2024-02-15",
                        "quantity": "1.2500",
                        "estimatedCostBasisUsd": 2650.00,
                        "holdingPeriod": "long-term",
                    },
                    {
                        "acquiredAt": "2026-03-10",
                        "quantity": "1.2500",
                        "estimatedCostBasisUsd": 3925.00,
                        "holdingPeriod": "short-term",
                    },
                ],
            }
        ],
        "security": {
            "requiresSeedPhrase": False,
            "requiresPrivateKey": False,
            "requiresWalletApproval": False,
            "custody": False,
        },
    }


def mock_sale(payload: dict[str, Any]) -> dict[str, Any]:
    amount = safe_float(payload.get("amount"), 1.0)
    sale_price = safe_float(payload.get("salePriceUsd"), 2500.0)
    proceeds = round(amount * sale_price, 2)
    estimated_basis = round(proceeds * 0.58, 2)
    estimated_gain = round(proceeds - estimated_basis, 2)
    estimated_tax = round(max(estimated_gain, 0) * 0.24, 2)

    return {
        "mode": "mock",
        "wallet": payload.get("wallet", ""),
        "token": payload.get("token", "ETH"),
        "amount": amount,
        "salePriceUsd": sale_price,
        "grossProceedsUsd": proceeds,
        "estimatedCostBasisUsd": estimated_basis,
        "estimatedGainUsd": estimated_gain,
        "estimatedTaxImpactUsd": estimated_tax,
        "takeHomeEstimateUsd": round(proceeds - estimated_tax, 2),
        "disclaimer": "Estimated tax-planning information only. Not tax, legal, accounting, or financial advice.",
    }


def safe_float(value: Any, fallback: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return fallback
    return number if number >= 0 else fallback


class Handler(BaseHTTPRequestHandler):
    server_version = "ShieldMendAIBackend/0.1"

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_common_headers()
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/health":
            self.write_json({"ok": True, "service": "shieldmendai-backend"})
            return
        if self.path == "/api/status":
            self.write_json(status_payload())
            return
        self.write_json({"error": "not_found"}, status=404)

    def do_POST(self) -> None:
        payload = self.read_json()
        if payload is None:
            self.write_json({"error": "invalid_json"}, status=400)
            return

        if self.path == "/api/scan-wallet":
            wallet = str(payload.get("wallet", "")).strip()
            if not WALLET_RE.match(wallet):
                self.write_json({"error": "invalid_wallet", "message": "Use a public EVM wallet address."}, status=400)
                return
            self.write_json(mock_scan(wallet))
            return

        if self.path == "/api/simulate-sale":
            self.write_json(mock_sale(payload))
            return

        self.write_json({"error": "not_found"}, status=404)

    def read_json(self) -> dict[str, Any] | None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        if length > 1_000_000:
            return None
        raw = self.rfile.read(length)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def write_json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_common_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_common_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", os.environ.get("SHIELDMEND_ALLOWED_ORIGIN", "*"))
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-store")

    def log_message(self, format: str, *args: Any) -> None:
        print("%s - %s" % (self.address_string(), format % args))


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"ShieldMendAI backend listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
