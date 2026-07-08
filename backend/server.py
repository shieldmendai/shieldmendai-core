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
import os
import re
import shlex
import socket
import threading
import time
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib import error, parse, request


HOST = os.environ.get("SHIELDMEND_HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT") or os.environ.get("SHIELDMEND_PORT", "8787"))
RPC_TIMEOUT_SECONDS = 5
BETA_DOWNLOAD_TOKEN_SECONDS = 30 * 60
BETA_APK_FILENAME = "ShieldMendAI-beta-0.1-debug.apk"
APK_CONTENT_TYPE = "application/vnd.android.package-archive"
WALLET_SCAN_CACHE_TTL_SECONDS = 5 * 60
WALLET_SCAN_COOLDOWN_SECONDS = 2 * 60
WALLET_SCAN_DAILY_LIMIT = 100
TOKEN_METADATA_CACHE_TTL_SECONDS = 30 * 24 * 60 * 60
WALLET_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
SHA256_HEX_RE = re.compile(r"^[a-fA-F0-9]{64}$")
ALLOWED_CORS_ORIGINS = {
    "capacitor://localhost",
    "http://localhost",
    "https://localhost",
    "https://shieldmendai.com",
    "https://www.shieldmendai.com",
}
LOCAL_DEV_ORIGIN_RE = re.compile(r"^http://(localhost|127\.0\.0\.1)(:\d{1,5})?$")
BASE_CHAIN_ID = 8453
WALLET_SCAN_CACHE: dict[str, dict[str, Any]] = {}
WALLET_SCAN_ACTIVITY: dict[str, dict[str, Any]] = {}
TOKEN_METADATA_CACHE: dict[str, dict[str, Any]] = {}
CACHE_LOCK = threading.Lock()
LFI_CONTRACT_ADDRESS = "0x3722264ab15a1dfce5a5af89e6547f7949a8aba3"
COMMON_TOKEN_RANKS = {
    "ETH": 10,
    "WETH": 10,
    "USDC": 20,
    "CBBTC": 30,
    "LFI": 40,
    "LIENFI": 40,
}
SPAM_WORD_RE = re.compile(
    r"(https?://|www\.|\.com|\.xyz|\.top|airdrop|claim|reward|bonus|visit|voucher|promo|gift|"
    r"free|win|winner|drop|telegram|t\.me|discord|whatsapp)",
    re.IGNORECASE,
)


def load_env_file() -> None:
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.is_file():
        return
    for raw_line in env_path.read_text(errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        if not name or name in os.environ:
            continue
        os.environ[name] = value.strip().strip("'\"")


load_env_file()


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
            "ALCHEMY_BASE_API_KEY",
            "ALCHEMY_BASE_RPC_URL",
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


def beta_apk_accel_path() -> str | None:
    value = os.environ.get("BETA_APK_ACCEL_PATH", "").strip()
    parsed = parse.urlparse(value)
    if (
        value.startswith("/_shieldmendai_private_apk/")
        and not parsed.scheme
        and not parsed.netloc
        and ".." not in Path(parsed.path).parts
    ):
        return value
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


def parse_byte_range(range_header: str, file_size: int) -> tuple[int, int] | None:
    if not range_header.startswith("bytes=") or file_size <= 0:
        return None

    requested = range_header.removeprefix("bytes=").split(",", 1)[0].strip()
    raw_start, separator, raw_end = requested.partition("-")
    if not separator:
        return None

    try:
        if raw_start == "":
            suffix_length = int(raw_end)
            if suffix_length <= 0:
                return None
            start = max(file_size - suffix_length, 0)
            end = file_size - 1
        else:
            start = int(raw_start)
            end = int(raw_end) if raw_end else file_size - 1
    except ValueError:
        return None

    if start < 0 or end < start or start >= file_size:
        return None
    return start, min(end, file_size - 1)


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


def rpc_batch_call(rpc_url: str, calls: list[tuple[str, list[Any]]]) -> list[Any]:
    if not rpc_url:
        raise RpcError("not_configured")
    if not calls:
        return []

    body = json.dumps(
        [
            {
                "jsonrpc": "2.0",
                "id": index,
                "method": method,
                "params": params,
            }
            for index, (method, params) in enumerate(calls, start=1)
        ]
    ).encode("utf-8")
    rpc_request = request.Request(
        rpc_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(rpc_request, timeout=RPC_TIMEOUT_SECONDS) as response:
            raw = response.read(5_000_000)
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

    if not isinstance(payload, list):
        raise RpcError("invalid_response")

    by_id = {item.get("id"): item for item in payload if isinstance(item, dict)}
    results: list[Any] = []
    for index in range(1, len(calls) + 1):
        item = by_id.get(index)
        if not item or item.get("error") or "result" not in item:
            results.append(None)
        else:
            results.append(item["result"])
    return results


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


def alchemy_base_rpc_url() -> str:
    value = os.environ.get("ALCHEMY_BASE_RPC_URL", "").strip()
    parsed = parse.urlparse(value)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return value
    return ""


def alchemy_base_configured() -> bool:
    return bool(alchemy_base_rpc_url())


def hex_quantity_to_int(value: Any) -> int:
    if not isinstance(value, str):
        return 0
    try:
        if value.startswith("0x"):
            return int(value, 16)
        return int(value)
    except ValueError:
        return 0


def safe_decimals(value: Any) -> int:
    if isinstance(value, int):
        decimals = value
    elif isinstance(value, str) and value.startswith("0x"):
        decimals = hex_quantity_to_int(value)
    else:
        try:
            decimals = int(value)
        except (TypeError, ValueError):
            decimals = 18
    return decimals if 0 <= decimals <= 255 else 18


def format_token_balance(raw_balance: int, decimals: int) -> str:
    value = Decimal(raw_balance) / (Decimal(10) ** Decimal(decimals))
    formatted = format(value.normalize(), "f")
    if "." in formatted:
        formatted = formatted.rstrip("0").rstrip(".")
    return formatted or "0"


def fallback_token_metadata(contract_address: str) -> dict[str, Any]:
    short = short_contract_address(contract_address)
    return {
        "symbol": short,
        "name": f"Token {short}",
        "decimals": 18,
    }


def short_contract_address(address: str) -> str:
    if len(address) <= 14:
        return address
    return f"{address[:6]}...{address[-4:]}"


def parse_balance_number(formatted_balance: str) -> float | None:
    try:
        value = Decimal(str(formatted_balance))
    except Exception:
        return None
    if not value.is_finite():
        return None
    return float(value)


def token_display_metadata(contract_address: str, symbol: Any, name: Any) -> tuple[str, str]:
    if contract_address.lower() == LFI_CONTRACT_ADDRESS:
        return "LFI", "LienFi"
    display_symbol = str(symbol or "").strip()
    display_name = str(name or "").strip()
    short = short_contract_address(contract_address)
    if not display_symbol:
        display_symbol = short
    if not display_name:
        display_name = f"Token {short}"
    return display_symbol[:40], display_name[:120]


def token_quality_fields(
    contract_address: str,
    symbol: Any,
    name: Any,
    formatted_balance: str,
) -> dict[str, Any]:
    display_symbol, display_name = token_display_metadata(contract_address, symbol, name)
    short = short_contract_address(contract_address)
    symbol_upper = display_symbol.upper()
    name_upper = display_name.upper()
    is_common = (
        symbol_upper in COMMON_TOKEN_RANKS
        or name_upper in COMMON_TOKEN_RANKS
        or contract_address.lower() == LFI_CONTRACT_ADDRESS
    )
    rank = min(
        COMMON_TOKEN_RANKS.get(symbol_upper, 500),
        COMMON_TOKEN_RANKS.get(name_upper, 500),
    )
    if contract_address.lower() == LFI_CONTRACT_ADDRESS:
        rank = COMMON_TOKEN_RANKS["LFI"]

    balance_number = parse_balance_number(formatted_balance)
    is_likely_dust = (
        balance_number is not None
        and balance_number > 0
        and Decimal(str(formatted_balance)) < Decimal("0.000000000001")
    )
    compact_symbol = re.sub(r"[^A-Za-z0-9$._-]", "", display_symbol)
    fallback_like = display_symbol == short or display_name == f"Token {short}"
    is_nonsense = len(compact_symbol) < max(1, min(len(display_symbol), 3) // 2)
    is_suspiciously_long = len(display_symbol) > 18 or len(display_name) > 72
    has_spam_words = bool(SPAM_WORD_RE.search(f"{display_symbol} {display_name}"))
    is_likely_spam = not is_common and (
        fallback_like
        or is_nonsense
        or is_suspiciously_long
        or has_spam_words
    )

    if is_likely_spam:
        rank = max(rank, 900)
    elif is_likely_dust and not is_common:
        rank = max(rank, 700)

    fields: dict[str, Any] = {
        "displaySymbol": display_symbol,
        "displayName": display_name,
        "shortContractAddress": short,
        "isLikelyDust": bool(is_likely_dust),
        "isLikelySpam": bool(is_likely_spam),
        "displayRank": rank,
    }
    if balance_number is not None:
        fields["balanceNumber"] = balance_number
    return fields


def cached_token_metadata(contract_address: str) -> dict[str, Any] | None:
    key = contract_address.lower()
    now = time.time()
    with CACHE_LOCK:
        cached = TOKEN_METADATA_CACHE.get(key)
        if cached and now - float(cached["storedAt"]) < TOKEN_METADATA_CACHE_TTL_SECONDS:
            return dict(cached["metadata"])
    return None


def store_token_metadata(contract_address: str, metadata: dict[str, Any]) -> None:
    key = contract_address.lower()
    with CACHE_LOCK:
        TOKEN_METADATA_CACHE[key] = {
            "storedAt": time.time(),
            "metadata": dict(metadata),
        }


def normalize_token_metadata(contract_address: str, payload: Any) -> dict[str, Any]:
    fallback = fallback_token_metadata(contract_address)
    if not isinstance(payload, dict):
        return fallback
    symbol = str(payload.get("symbol") or "").strip() or fallback["symbol"]
    name = str(payload.get("name") or "").strip() or fallback["name"]
    decimals = safe_decimals(payload.get("decimals", fallback["decimals"]))
    return {
        "symbol": symbol[:40],
        "name": name[:120],
        "decimals": decimals,
    }


def fetch_token_metadata(rpc_url: str, contract_addresses: list[str]) -> dict[str, dict[str, Any]]:
    metadata_by_contract: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    for contract_address in contract_addresses:
        cached = cached_token_metadata(contract_address)
        if cached is not None:
            metadata_by_contract[contract_address.lower()] = cached
        else:
            missing.append(contract_address)

    if missing:
        calls = [("alchemy_getTokenMetadata", [contract_address]) for contract_address in missing]
        try:
            results = rpc_batch_call(rpc_url, calls)
        except RpcError:
            results = [None] * len(missing)

        for contract_address, result in zip(missing, results):
            metadata = normalize_token_metadata(contract_address, result)
            metadata_by_contract[contract_address.lower()] = metadata
            store_token_metadata(contract_address, metadata)

    return metadata_by_contract


def wallet_cache_payload(wallet_key: str, message: str | None = None) -> dict[str, Any] | None:
    now = time.time()
    with CACHE_LOCK:
        cached = WALLET_SCAN_CACHE.get(wallet_key)
        if not cached:
            return None
        age_seconds = max(0, int(now - float(cached["storedAt"])))
        payload = dict(cached["payload"])
    payload["cached"] = True
    payload["cacheAgeSeconds"] = age_seconds
    payload["refreshAvailableInSeconds"] = max(0, WALLET_SCAN_CACHE_TTL_SECONDS - age_seconds)
    if message:
        payload["message"] = message
    return payload


def fresh_scan_allowed(wallet_key: str) -> bool:
    now = time.time()
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    with CACHE_LOCK:
        activity = WALLET_SCAN_ACTIVITY.get(wallet_key)
        if activity and activity.get("day") != day:
            activity = None
        if activity:
            if now - float(activity.get("lastFreshAt", 0)) < WALLET_SCAN_COOLDOWN_SECONDS:
                return False
            if int(activity.get("count", 0)) >= WALLET_SCAN_DAILY_LIMIT:
                return False
        return True


def record_fresh_scan(wallet_key: str) -> None:
    now = time.time()
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    with CACHE_LOCK:
        activity = WALLET_SCAN_ACTIVITY.get(wallet_key)
        if not activity or activity.get("day") != day:
            activity = {"day": day, "count": 0, "lastFreshAt": 0}
        activity["count"] = int(activity.get("count", 0)) + 1
        activity["lastFreshAt"] = now
        WALLET_SCAN_ACTIVITY[wallet_key] = activity


def store_wallet_scan(wallet_key: str, payload: dict[str, Any]) -> None:
    with CACHE_LOCK:
        WALLET_SCAN_CACHE[wallet_key] = {
            "storedAt": time.time(),
            "payload": dict(payload),
        }


def alchemy_token_scan(wallet: str) -> dict[str, Any]:
    rpc_url = alchemy_base_rpc_url()
    if not rpc_url:
        raise RpcError("not_configured")

    wallet_key = wallet.lower()
    cached = wallet_cache_payload(wallet_key, "Updated recently. Showing your latest saved scan.")
    if cached and cached["cacheAgeSeconds"] < WALLET_SCAN_CACHE_TTL_SECONDS:
        return cached
    if cached and not fresh_scan_allowed(wallet_key):
        cached["refreshAvailableInSeconds"] = max(0, WALLET_SCAN_COOLDOWN_SECONDS - cached["cacheAgeSeconds"])
        cached["message"] = "Updated recently. Showing your latest saved scan."
        return cached

    balances_result = rpc_call(rpc_url, "alchemy_getTokenBalances", [wallet, "erc20"])
    if not isinstance(balances_result, dict):
        raise RpcError("invalid_response")

    raw_balances = balances_result.get("tokenBalances")
    if not isinstance(raw_balances, list):
        raise RpcError("invalid_response")

    nonzero_balances: list[tuple[str, int, str]] = []
    for item in raw_balances:
        if not isinstance(item, dict):
            continue
        contract_address = str(item.get("contractAddress") or "").strip()
        raw_balance_value = item.get("tokenBalance")
        raw_balance = hex_quantity_to_int(raw_balance_value)
        if not WALLET_RE.match(contract_address) or raw_balance <= 0:
            continue
        nonzero_balances.append((contract_address, raw_balance, str(raw_balance_value)))

    metadata_by_contract = fetch_token_metadata(
        rpc_url,
        [contract_address for contract_address, _, _ in nonzero_balances],
    )
    tokens = []
    for contract_address, raw_balance, raw_balance_value in nonzero_balances:
        metadata = metadata_by_contract.get(contract_address.lower()) or fallback_token_metadata(contract_address)
        decimals = safe_decimals(metadata.get("decimals"))
        symbol = metadata.get("symbol") or short_contract_address(contract_address)
        name = metadata.get("name") or f"Token {short_contract_address(contract_address)}"
        formatted_balance = format_token_balance(raw_balance, decimals)
        quality_fields = token_quality_fields(contract_address, symbol, name, formatted_balance)
        tokens.append(
            {
                "contractAddress": contract_address,
                "symbol": symbol,
                "name": name,
                "decimals": decimals,
                "rawBalance": raw_balance_value if raw_balance_value.startswith("0x") else str(raw_balance),
                "formattedBalance": formatted_balance,
                **quality_fields,
            }
        )

    visible_token_count = sum(1 for token in tokens if not token["isLikelySpam"] and not token["isLikelyDust"])
    likely_spam_count = sum(1 for token in tokens if token["isLikelySpam"])
    likely_dust_count = sum(1 for token in tokens if token["isLikelyDust"])
    important_token_count = sum(1 for token in tokens if int(token["displayRank"]) < 100)
    record_fresh_scan(wallet_key)
    payload: dict[str, Any] = {
        "ok": True,
        "wallet": wallet,
        "chainId": BASE_CHAIN_ID,
        "scanMode": "alchemy-token-balances",
        "mode": "alchemy-token-balances",
        "cached": False,
        "cacheAgeSeconds": 0,
        "refreshAvailableInSeconds": WALLET_SCAN_CACHE_TTL_SECONDS,
        "tokenCount": len(tokens),
        "visibleTokenCount": visible_token_count,
        "likelySpamCount": likely_spam_count,
        "likelyDustCount": likely_dust_count,
        "importantTokenCount": important_token_count,
        "tokenQualityMode": "beta-basic-filtering",
        "tokens": tokens,
        "readOnly": True,
        "message": "Token scan active.",
        "security": {
            "requiresSeedPhrase": False,
            "requiresPrivateKey": False,
            "requiresWalletApproval": False,
            "custody": False,
        },
    }
    store_wallet_scan(wallet_key, payload)
    return payload


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
    alchemy_base_ready = alchemy_base_configured()
    return {
        "backend": "live",
        "walletScan": "live-basic" if rpc["rpcLive"] else "mock",
        "alchemyConfigured": env_present("ALCHEMY_BASE_API_KEY") or alchemy_base_ready,
        "alchemyBaseConfigured": alchemy_base_ready,
        "tokenScanner": "alchemy" if alchemy_base_ready else "unconfigured",
        "cacheEnabled": True,
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
        self.handle_get_or_head(send_body=True)

    def do_HEAD(self) -> None:
        self.handle_get_or_head(send_body=False)

    def handle_get_or_head(self, *, send_body: bool) -> None:
        parsed_path = parse.urlparse(self.path)
        if parsed_path.path == "/health":
            self.write_json({"ok": True, "service": "shieldmendai-backend"}, send_body=send_body)
            return
        if parsed_path.path == "/api/status":
            self.write_json(status_payload(), send_body=send_body)
            return
        if parsed_path.path == "/api/rpc-diagnostics":
            self.write_json(rpc_diagnostics(), send_body=send_body)
            return
        if parsed_path.path == "/api/beta-access/download":
            params = parse.parse_qs(parsed_path.query)
            token = params.get("token", [""])[0]
            self.write_beta_apk(token, send_body=send_body)
            return
        self.write_json({"error": "not_found"}, status=404, send_body=send_body)

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
            try:
                self.write_json(alchemy_token_scan(wallet))
                return
            except RpcError:
                pass
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

    def write_json(self, payload: dict[str, Any], status: int = 200, *, send_body: bool = True) -> None:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_common_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def write_beta_apk(self, token: str, *, send_body: bool) -> None:
        path = beta_apk_path()
        if path is None:
            self.write_json({"error": "apk_unavailable"}, status=404)
            return
        if not verify_beta_download_token(token):
            self.write_json({"error": "invalid_or_expired_token"}, status=403)
            return

        accel_path = beta_apk_accel_path()
        if accel_path:
            self.send_response(200)
            self.send_common_headers()
            self.send_apk_headers(path.stat().st_size)
            self.send_header("X-Accel-Redirect", accel_path)
            self.end_headers()
            return

        file_size = path.stat().st_size
        range_header = self.headers.get("Range")
        range_start = 0
        range_end = file_size - 1
        status = 200

        if range_header:
            parsed_range = parse_byte_range(range_header, file_size)
            if parsed_range is None:
                self.send_response(416)
                self.send_common_headers()
                self.send_header("Content-Range", f"bytes */{file_size}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            range_start, range_end = parsed_range
            status = 206

        content_length = range_end - range_start + 1
        body = b""
        if send_body:
            with path.open("rb") as apk_file:
                apk_file.seek(range_start)
                body = apk_file.read(content_length)
            content_length = len(body)

        self.send_response(status)
        self.send_common_headers()
        self.send_apk_headers(content_length)
        if status == 206:
            self.send_header("Content-Range", f"bytes {range_start}-{range_end}/{file_size}")
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def send_apk_headers(self, content_length: int) -> None:
        self.send_header("Content-Type", APK_CONTENT_TYPE)
        self.send_header("Content-Disposition", f'attachment; filename="{BETA_APK_FILENAME}"')
        self.send_header("Content-Length", str(content_length))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("X-Content-Type-Options", "nosniff")

    def send_common_headers(self) -> None:
        allowed_origin = allowed_cors_origin(self.headers.get("Origin"))
        if allowed_origin:
            self.send_header("Access-Control-Allow-Origin", allowed_origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Range")
        self.send_header("Cache-Control", "private, no-store")

    def log_message(self, format: str, *args: Any) -> None:
        print("%s - %s" % (self.address_string(), format % args))


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"ShieldMendAI backend listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
