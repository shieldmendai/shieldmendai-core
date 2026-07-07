#!/usr/bin/env python3
"""Read-only ShieldMendAI backend foundation.

This server intentionally avoids custody, private keys, seed phrases, approvals,
and trading operations. Initial scan and simulation responses are mock data until
read-only provider adapters and a real tax engine are implemented.
"""

from __future__ import annotations

import json
import base64
import hashlib
import hmac
import mimetypes
import os
import re
import shlex
import socket
import time
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib import error, parse, request


HOST = os.environ.get("SHIELDMEND_HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT") or os.environ.get("SHIELDMEND_PORT", "8787"))
RPC_TIMEOUT_SECONDS = 5
BETA_DOWNLOAD_TOKEN_SECONDS = 600
BETA_APK_FILENAME = "ShieldMendAI-beta-0.1-debug.apk"
WALLET_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
SHA256_HEX_RE = re.compile(r"^[a-fA-F0-9]{64}$")
ALLOWED_CORS_ORIGINS = {
    "https://shieldmendai.com",
    "https://www.shieldmendai.com",
}
LOCAL_DEV_ORIGIN_RE = re.compile(r"^http://(localhost|127\.0\.0\.1)(:\d{1,5})?$")


class RpcError(RuntimeError):
    def __init__(self, error_type: str) -> None:
        super().__init__(error_type)
        self.error_type = error_type


def env_present(name: str) -> bool:
    return bool(os.environ.get(name))


def provider_configured() -> bool:
    return any(
        env_present(name)
        for name in (
            "BASE_RPC_URL",
            "BASE_RPC_URLS",
            "BASESCAN_API_KEY",
            "GOPLUS_API_KEY",
            "COINGECKO_API_KEY",
            "COVALENT_API_KEY",
            "MORALIS_API_KEY",
            "SIMPLEHASH_API_KEY",
        )
    )


def allowed_cors_origin(origin: str | None) -> str | None:
    if not origin:
        return None
    if origin in ALLOWED_CORS_ORIGINS:
        return origin
    if LOCAL_DEV_ORIGIN_RE.fullmatch(origin):
        return origin
    return None


def env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def safe_hash_match(value: str, expected_hash: str) -> bool:
    expected = expected_hash.strip().lower()
    if not SHA256_HEX_RE.fullmatch(expected):
        return False
    return hmac.compare_digest(sha256_hex(value), expected)


def parse_creator_code_hashes(value: str) -> list[tuple[str, str]]:
    creators: list[tuple[str, str]] = []
    for item in value.split(","):
        raw_hash, separator, raw_label = item.strip().partition(":")
        if not separator:
            continue
        code_hash = raw_hash.strip().lower()
        label = raw_label.strip()
        if SHA256_HEX_RE.fullmatch(code_hash) and label:
            creators.append((code_hash, label[:80]))
    return creators


def beta_apk_path() -> Path | None:
    value = os.environ.get("BETA_APK_FILE", "").strip()
    if not value:
        return None
    path = Path(value)
    if path.is_file():
        return path
    return None


def beta_download_secret() -> bytes | None:
    secret = os.environ.get("BETA_DOWNLOAD_SECRET", "").strip()
    return secret.encode("utf-8") if secret else None


def public_api_base_url() -> str:
    value = os.environ.get("PUBLIC_API_BASE_URL", "https://api.shieldmendai.com").strip()
    parsed = parse.urlparse(value)
    if parsed.scheme in {"https", "http"} and parsed.netloc:
        return value.rstrip("/")
    return "https://api.shieldmendai.com"


def sign_beta_download_token(expires_at: int) -> str | None:
    secret = beta_download_secret()
    if not secret:
        return None
    payload = json.dumps({"exp": expires_at}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    signature = hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"{payload_b64}.{signature_b64}"


def decode_urlsafe_b64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def verify_beta_download_token(token: str) -> bool:
    secret = beta_download_secret()
    if not secret:
        return False
    payload_b64, separator, signature_b64 = token.partition(".")
    if not separator or not payload_b64 or not signature_b64:
        return False

    expected = hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
    try:
        provided = decode_urlsafe_b64(signature_b64)
        payload = json.loads(decode_urlsafe_b64(payload_b64).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return False

    if not hmac.compare_digest(provided, expected):
        return False

    try:
        expires_at = int(payload.get("exp", 0))
    except (TypeError, ValueError):
        return False
    return expires_at >= int(time.time())


def beta_download_url() -> str | None:
    if beta_apk_path() is None:
        return None
    token = sign_beta_download_token(int(time.time()) + BETA_DOWNLOAD_TOKEN_SECONDS)
    if token is None:
        return None
    return f"{public_api_base_url()}/api/beta-access/download?token={parse.quote(token)}"


def beta_access_response(payload: dict[str, Any]) -> dict[str, Any]:
    if not env_flag("BETA_ACCESS_ENABLED"):
        return {
            "ok": False,
            "accessGranted": False,
            "message": "Beta access is not open yet.",
        }

    code = str(payload.get("code", "")).strip()
    if not code:
        return {
            "ok": False,
            "accessGranted": False,
            "message": "That access code was not recognized.",
        }

    access_type: str | None = None
    creator: str | None = None
    if safe_hash_match(code, os.environ.get("BETA_FRIEND_CODE_HASH", "")):
        access_type = "friend"
    else:
        for code_hash, label in parse_creator_code_hashes(os.environ.get("BETA_CREATOR_CODE_HASHES", "")):
            if safe_hash_match(code, code_hash):
                access_type = "creator"
                creator = label
                break

    if access_type is None:
        return {
            "ok": False,
            "accessGranted": False,
            "message": "That access code was not recognized.",
        }

    download_url = beta_download_url()
    response: dict[str, Any] = {
        "ok": True,
        "accessGranted": True,
        "accessType": access_type,
        "apkAvailable": download_url is not None,
        "message": (
            "Access approved. Your ShieldMendAI beta download is ready."
            if download_url
            else "Access approved. APK download is not available yet."
        ),
    }
    if creator:
        response["creator"] = creator
    if download_url:
        response["downloadUrl"] = download_url
    return response


def split_rpc_env_value(value: str) -> list[str]:
    try:
        parts = shlex.split(value)
    except ValueError:
        parts = value.split()
    candidates: list[str] = []
    for part in parts:
        candidates.extend(part.split(","))
    return [candidate.strip().strip("'\"") for candidate in candidates]


def rpc_candidates() -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()
    for name in ("BASE_RPC_URL", "BASE_RPC_URLS"):
        value = os.environ.get(name, "")
        for candidate in split_rpc_env_value(value):
            if not candidate:
                continue
            parsed = parse.urlparse(candidate)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                continue
            if candidate not in seen:
                seen.add(candidate)
                candidates.append(candidate)
    return candidates


def rpc_call(rpc_url: str, method: str, params: list[Any]) -> Any:
    if not rpc_url:
        raise RpcError("not_configured")

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
    except TimeoutError as exc:
        raise RpcError("timeout") from exc
    except socket.timeout as exc:
        raise RpcError("timeout") from exc
    except error.HTTPError as exc:
        raise RpcError("http_error") from exc
    except error.URLError as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, TimeoutError | socket.timeout):
            raise RpcError("timeout") from exc
        raise RpcError("url_error") from exc
    except OSError as exc:
        raise RpcError("network_error") from exc

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RpcError("invalid_json") from exc

    if not isinstance(payload, dict):
        raise RpcError("invalid_response")
    if payload.get("error"):
        raise RpcError("rpc_error")
    if "result" not in payload:
        raise RpcError("missing_result")
    return payload["result"]


def get_chain_id(rpc_url: str) -> int:
    result = rpc_call(rpc_url, "eth_chainId", [])
    if not isinstance(result, str) or not result.startswith("0x"):
        raise RpcError("invalid_chain_id")
    try:
        return int(result, 16)
    except ValueError as exc:
        raise RpcError("invalid_chain_id") from exc


def get_native_balance(rpc_url: str, wallet: str) -> int:
    result = rpc_call(rpc_url, "eth_getBalance", [wallet, "latest"])
    if not isinstance(result, str) or not result.startswith("0x"):
        raise RpcError("invalid_balance")
    try:
        return int(result, 16)
    except ValueError as exc:
        raise RpcError("invalid_balance") from exc


def wei_to_eth(wei: int) -> str:
    value = Decimal(wei) / Decimal(10**18)
    return format(value, "f")


def test_rpc_candidate(index: int, rpc_url: str) -> dict[str, Any]:
    result: dict[str, Any] = {"index": index, "success": False}
    try:
        result["chainId"] = get_chain_id(rpc_url)
        result["success"] = True
    except RpcError as exc:
        result["errorType"] = exc.error_type
    return result


def rpc_diagnostics() -> dict[str, Any]:
    candidates = rpc_candidates()
    candidate_results = [
        test_rpc_candidate(index, rpc_url)
        for index, rpc_url in enumerate(candidates, start=1)
    ]
    live_result = next((item for item in candidate_results if item["success"]), None)
    payload: dict[str, Any] = {
        "rpcConfigured": bool(candidates),
        "candidateCount": len(candidates),
        "candidateResults": candidate_results,
    }
    if live_result:
        payload["chainId"] = live_result["chainId"]
    return payload


def working_rpc() -> tuple[str, int] | None:
    for rpc_url in rpc_candidates():
        try:
            return rpc_url, get_chain_id(rpc_url)
        except RpcError:
            continue
    return None


def rpc_status() -> dict[str, Any]:
    diagnostics = rpc_diagnostics()
    chain_id = diagnostics.get("chainId")
    payload: dict[str, Any] = {
        "rpcConfigured": diagnostics["rpcConfigured"],
        "rpcCandidateCount": diagnostics["candidateCount"],
        "rpcLive": chain_id is not None,
    }
    if chain_id is not None:
        payload["chainId"] = chain_id
    return payload


def status_payload() -> dict[str, Any]:
    rpc = rpc_status()
    return {
        "backend": "live",
        "walletScan": "live-basic" if rpc["rpcLive"] else "mock",
        "taxEngine": "mock",
        "readOnlyProviderConfigured": provider_configured(),
        "basescanConfigured": env_present("BASESCAN_API_KEY"),
        "zeroxConfigured": env_present("ZEROX_API_KEY"),
        "goplusConfigured": env_present("GOPLUS_API_KEY"),
        **rpc,
        "custody": False,
        "requiresSeedPhrase": False,
        "requiresPrivateKey": False,
        "requiresWalletApproval": False,
    }


def live_basic_scan(wallet: str, rpc_url: str, chain_id: int) -> dict[str, Any]:
    balance_wei = get_native_balance(rpc_url, wallet)
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
        parsed_path = parse.urlparse(self.path)
        if parsed_path.path == "/health":
            self.write_json({"ok": True, "service": "shieldmendai-backend"})
            return
        if parsed_path.path == "/api/status":
            self.write_json(status_payload())
            return
        if parsed_path.path == "/api/rpc-diagnostics":
            self.write_json(rpc_diagnostics())
            return
        if parsed_path.path == "/api/beta-access/download":
            params = parse.parse_qs(parsed_path.query)
            token = params.get("token", [""])[0]
            self.write_beta_apk(token)
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
            rpc = working_rpc()
            if rpc:
                rpc_url, chain_id = rpc
                try:
                    self.write_json(live_basic_scan(wallet, rpc_url, chain_id))
                    return
                except RpcError:
                    pass
            self.write_json(mock_scan(wallet))
            return

        if self.path == "/api/simulate-sale":
            self.write_json(mock_sale(payload))
            return

        if self.path == "/api/beta-access/verify":
            self.write_json(beta_access_response(payload))
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

    def write_beta_apk(self, token: str) -> None:
        path = beta_apk_path()
        if path is None:
            self.write_json({"error": "apk_unavailable"}, status=404)
            return
        if not verify_beta_download_token(token):
            self.write_json({"error": "invalid_or_expired_token"}, status=403)
            return

        content_type = mimetypes.guess_type(BETA_APK_FILENAME)[0] or "application/vnd.android.package-archive"
        self.send_response(200)
        self.send_common_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{BETA_APK_FILENAME}"')
        self.send_header("Content-Length", str(path.stat().st_size))
        self.end_headers()
        with path.open("rb") as apk_file:
            while chunk := apk_file.read(1024 * 1024):
                self.wfile.write(chunk)

    def send_common_headers(self) -> None:
        allowed_origin = allowed_cors_origin(self.headers.get("Origin"))
        if allowed_origin:
            self.send_header("Access-Control-Allow-Origin", allowed_origin)
            self.send_header("Vary", "Origin")
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
