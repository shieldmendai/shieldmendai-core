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
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib import error, request


HOST = os.environ.get("SHIELDMEND_HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT") or os.environ.get("SHIELDMEND_PORT", "8787"))
RPC_TIMEOUT_SECONDS = 5
WALLET_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def env_present(name: str) -> bool:
    return bool(os.environ.get(name))


def provider_configured() -> bool:
    return any(
        env_present(name)
        for name in (
            "BASE_RPC_URL",
            "BASESCAN_API_KEY",
            "COINGECKO_API_KEY",
            "COVALENT_API_KEY",
            "MORALIS_API_KEY",
            "SIMPLEHASH_API_KEY",
        )
    )


def rpc_call(method: str, params: list[Any]) -> Any:
    rpc_url = os.environ.get("BASE_RPC_URL")
    if not rpc_url:
        raise RuntimeError("BASE_RPC_URL is not configured")

    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }
    ).encode("utf-8")
    rpc_request = request.Request(
        rpc_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(rpc_request, timeout=RPC_TIMEOUT_SECONDS) as response:
            raw = response.read(1_000_000)
    except (TimeoutError, OSError, error.URLError, error.HTTPError) as exc:
        raise RuntimeError("RPC request failed") from exc

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("RPC response was not valid JSON") from exc

    if not isinstance(payload, dict):
        raise RuntimeError("RPC response was not an object")
    if payload.get("error"):
        raise RuntimeError("RPC returned an error")
    if "result" not in payload:
        raise RuntimeError("RPC response did not include a result")
    return payload["result"]


def get_chain_id() -> int:
    result = rpc_call("eth_chainId", [])
    if not isinstance(result, str) or not result.startswith("0x"):
        raise RuntimeError("RPC chain ID was not a hex string")
    return int(result, 16)


def get_native_balance(wallet: str) -> int:
    result = rpc_call("eth_getBalance", [wallet, "latest"])
    if not isinstance(result, str) or not result.startswith("0x"):
        raise RuntimeError("RPC native balance was not a hex string")
    return int(result, 16)


def wei_to_eth(wei: int) -> str:
    value = Decimal(wei) / Decimal(10**18)
    return format(value, "f")


def rpc_status() -> dict[str, Any]:
    if not env_present("BASE_RPC_URL"):
        return {"rpcConfigured": False, "rpcLive": False}
    try:
        chain_id = get_chain_id()
    except RuntimeError:
        return {"rpcConfigured": True, "rpcLive": False}
    return {"rpcConfigured": True, "rpcLive": True, "chainId": chain_id}


def status_payload() -> dict[str, Any]:
    rpc = rpc_status()
    return {
        "backend": "live",
        "walletScan": "live-basic" if rpc["rpcLive"] else "mock",
        "taxEngine": "mock",
        "readOnlyProviderConfigured": provider_configured(),
        "basescanConfigured": env_present("BASESCAN_API_KEY"),
        "goplusConfigured": env_present("GOPLUS_API_KEY"),
        **rpc,
        "custody": False,
        "requiresSeedPhrase": False,
        "requiresPrivateKey": False,
        "requiresWalletApproval": False,
    }


def live_basic_scan(wallet: str) -> dict[str, Any]:
    chain_id = get_chain_id()
    balance_wei = get_native_balance(wallet)
    return {
        "mode": "live-basic",
        "wallet": wallet,
        "chainId": chain_id,
        "nativeBalanceWei": str(balance_wei),
        "nativeBalanceEth": wei_to_eth(balance_wei),
        "readOnly": True,
        "message": "Live read-only RPC balance check. Token lots and tax lots still require transaction history adapters.",
        "security": {
            "requiresSeedPhrase": False,
            "requiresPrivateKey": False,
            "requiresWalletApproval": False,
            "custody": False,
        },
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
            if env_present("BASE_RPC_URL"):
                try:
                    self.write_json(live_basic_scan(wallet))
                    return
                except RuntimeError:
                    pass
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
