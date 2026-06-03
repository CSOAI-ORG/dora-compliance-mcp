"""
MEOK Labs — Shared Authentication Middleware for MCP Servers
Deploy to: ~/clawd/meok-labs-engine/shared/auth_middleware.py
Every compliance MCP server imports this.

Usage in any server.py:
    import sys, os
    sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
    from auth_middleware import check_access, require_tier, audit_log, Tier

    @mcp.tool(name="my_tool")
    async def my_tool(query: str, api_key: str = "") -> str:
        allowed, msg, tier = check_access(api_key)
        if not allowed:
            return json.dumps({"error": msg, "upgrade_url": "https://councilof.ai"})
        # ... tool logic ...
        audit_log(api_key, "my_tool", "eu_ai_act", "result_summary", tier)
        return json.dumps(result)
"""

import os
import hashlib
import time
import json
from typing import Optional, Tuple
from enum import Enum


class Tier(str, Enum):
    FREE = "free"
    PAYG = "payg"            # pay-per-call via MEOK_PAYG_KEY env var (£0.05/call)
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


TIER_LIMITS = {
    Tier.FREE:          {"calls_per_day": 10,   "frameworks": 1,  "audit_trail": False},
    Tier.PAYG:          {"calls_per_day": -1,   "frameworks": -1, "audit_trail": True},
    Tier.STARTER:       {"calls_per_day": 100,  "frameworks": 1,  "audit_trail": False},
    Tier.PROFESSIONAL:  {"calls_per_day": 1000, "frameworks": 5,  "audit_trail": True},
    Tier.ENTERPRISE:    {"calls_per_day": -1,   "frameworks": -1, "audit_trail": True},
}

TIER_ORDER = [Tier.FREE, Tier.PAYG, Tier.STARTER, Tier.PROFESSIONAL, Tier.ENTERPRISE]

# ── Pay-per-call (PAYG) configuration ──────────────────────────────────
# Agents can opt into per-call billing instead of a subscription by setting
# the MEOK_PAYG_KEY env var. Each tool call deducts £0.05 (or whatever the
# rate is for that tool) from the balance fronted via the council storefront
# PAYG top-up page. When balance hits zero the tool returns a top-up URL.
PAYG_PRICE_PER_CALL_GBP = float(os.environ.get("MEOK_PAYG_RATE_GBP", "0.05"))
PAYG_TOPUP_URL = os.environ.get("MEOK_PAYG_TOPUP_URL", "https://councilof.ai/payg")
PAYG_X402_RECEIVER = os.environ.get("MEOK_X402_RECEIVER", "")  # USDC on Base L2 wallet
PAYG_BALANCE_FILE = os.path.join(os.path.expanduser("~/.meok"), "payg_balance.json")

# Set MEOK_PAYG_SERVER_URL on the client to use SERVER-SIDE balance tracking
# instead of the local-file fallback. With the server set, the customer's token
# resolves against Stripe customer metadata (the source of truth for real
# top-ups). Without the server, behaviour falls back to the local JSON file —
# useful for offline/single-machine testing but DOES NOT honour real Stripe
# top-ups. Strongly recommended for any agent that actually paid:
#   export MEOK_PAYG_SERVER_URL=https://meok-attestation-api.vercel.app/payg
PAYG_SERVER_URL = os.environ.get("MEOK_PAYG_SERVER_URL", "").rstrip("/")


def _payg_token_present() -> bool:
    """True iff the caller has opted into pay-per-call billing."""
    return bool(os.environ.get("MEOK_PAYG_KEY", "").strip())


def _payg_server_deduct(token: str, amount_gbp: float) -> Tuple[bool, float]:
    """Server-side deduction via the meok-attestation-api PAYG endpoint.

    Returns (success, remaining_gbp). On any failure (network, 5xx, malformed
    response), returns (False, 0.0) so the caller falls through to the upsell
    path. Never raises — we want the MCP tool to keep responding even if the
    PAYG server is briefly unreachable.
    """
    if not PAYG_SERVER_URL or not token:
        return False, 0.0
    import urllib.request as _ur
    import urllib.error as _ue
    payload = json.dumps({"token": token, "amount_gbp": amount_gbp}).encode("utf-8")
    req = _ur.Request(
        f"{PAYG_SERVER_URL}/deduct",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with _ur.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
        return bool(data.get("ok")), float(data.get("balance_gbp", 0.0))
    except _ue.HTTPError as e:
        # 402 = insufficient balance. Read body to surface remaining.
        try:
            data = json.loads(e.read())
        except Exception:
            data = {}
        return False, float(data.get("balance_gbp", 0.0))
    except Exception:
        return False, 0.0


def _payg_balance(token: str) -> float:
    """Read current balance (in GBP) for a PAYG token.

    Server mode: queries /payg/balance against MEOK_PAYG_SERVER_URL.
    Local mode (no server URL): reads ~/.meok/payg_balance.json (single-machine).
    """
    if not token:
        return 0.0
    if PAYG_SERVER_URL:
        import urllib.request as _ur
        try:
            with _ur.urlopen(f"{PAYG_SERVER_URL}/balance?token={token}", timeout=6) as resp:
                data = json.loads(resp.read())
            return float(data.get("balance_gbp", 0.0))
        except Exception:
            return 0.0
    _ensure_dir()
    bal = _load_json(PAYG_BALANCE_FILE)
    return float(bal.get(token, 0.0))


def _payg_deduct(token: str, amount_gbp: float) -> Tuple[bool, float]:
    """Try to deduct `amount_gbp` from balance. Returns (success, remaining).

    Routes to the server when MEOK_PAYG_SERVER_URL is set (the case for any
    real paying customer — Stripe customer metadata is the source of truth).
    Falls back to the local JSON file when no server is configured.
    """
    if not token:
        return False, 0.0
    if PAYG_SERVER_URL:
        return _payg_server_deduct(token, amount_gbp)
    _ensure_dir()
    bal = _load_json(PAYG_BALANCE_FILE)
    current = float(bal.get(token, 0.0))
    if current < amount_gbp:
        return False, current
    bal[token] = round(current - amount_gbp, 4)
    _save_json(PAYG_BALANCE_FILE, bal)
    return True, bal[token]


def payg_upsell_line(tool_name: str = "this tool") -> str:
    """Universal upsell line that always shows BOTH paths: subscription + PAYG.
    Drop this into any rate-limit response so callers always see both options.
    """
    return (
        f"PAYG (no subscription, £{PAYG_PRICE_PER_CALL_GBP:.2f}/call): "
        f"set MEOK_PAYG_KEY and top up at {PAYG_TOPUP_URL} — works with "
        f"agent-driven workflows. Or upgrade to a tier at https://councilof.ai."
    )

MEOK_DIR = os.path.expanduser("~/.meok")
USAGE_FILE = os.path.join(MEOK_DIR, "usage.json")
KEYS_FILE = os.path.join(MEOK_DIR, "api_keys.json")
AUDIT_FILE = os.path.join(MEOK_DIR, "audit_trail.jsonl")


def _ensure_dir():
    os.makedirs(MEOK_DIR, exist_ok=True)


def _load_json(path: str) -> dict:
    _ensure_dir()
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def _save_json(path: str, data: dict):
    _ensure_dir()
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def generate_api_key(tier: Tier, customer_name: str) -> str:
    """Generate a new API key for a customer. Run manually to onboard customers."""
    raw = f"meok_{tier.value}_{customer_name}_{time.time()}"
    key = f"meok_{hashlib.sha256(raw.encode()).hexdigest()[:32]}"
    
    keys = _load_json(KEYS_FILE)
    keys[key] = {
        "tier": tier.value,
        "customer": customer_name,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "active": True,
    }
    _save_json(KEYS_FILE, keys)
    return key


def get_tier_from_api_key(api_key: str) -> Tier:
    """Look up tier for an API key."""
    if not api_key:
        return Tier.FREE
    
    keys = _load_json(KEYS_FILE)
    if api_key in keys and keys[api_key].get("active", True):
        try:
            return Tier(keys[api_key]["tier"])
        except ValueError:
            return Tier.FREE
    
    return Tier.FREE


def check_access(api_key: str = "", framework: str = None) -> Tuple[bool, str, Tier]:
    """
    Main access control function. Returns (allowed, message, tier).
    Call at the start of every tool.

    Resolution order:
      1. PAYG: MEOK_PAYG_KEY env var → deduct from balance; reject with top-up URL when empty.
      2. Subscription: api_key tier → enforce daily rate limit.
      3. Anonymous free tier: 10 calls/day, capped.
    Free callers ALSO see PAYG as an alternative in the rate-limit response so
    they can opt into per-call billing without a subscription.
    """
    # ── PAYG path: env var beats subscription ──
    payg_token = os.environ.get("MEOK_PAYG_KEY", "").strip()
    if payg_token:
        ok, remaining = _payg_deduct(payg_token, PAYG_PRICE_PER_CALL_GBP)
        if ok:
            return True, f"OK (PAYG · £{remaining:.2f} remaining)", Tier.PAYG
        return (
            False,
            f"PAYG balance exhausted (£{remaining:.2f} left, needs £{PAYG_PRICE_PER_CALL_GBP:.2f}). "
            f"Top up at {PAYG_TOPUP_URL} — Stripe + USDC-on-Base both accepted.",
            Tier.PAYG,
        )

    # ── Subscription / free tier path ──
    tier = get_tier_from_api_key(api_key)
    limits = TIER_LIMITS[tier]

    # Rate limit check
    usage = _load_json(USAGE_FILE)
    today = time.strftime("%Y-%m-%d")
    key_hash = hashlib.sha256((api_key or "anon").encode()).hexdigest()[:12]
    day_key = f"{key_hash}:{today}"

    current = usage.get(day_key, 0)
    max_calls = limits["calls_per_day"]

    if max_calls != -1 and current >= max_calls:
        return (
            False,
            f"Rate limit reached ({max_calls}/day on {tier.value} tier). "
            f"{payg_upsell_line()}",
            tier,
        )

    # Record usage
    usage[day_key] = current + 1
    # Clean old entries (keep last 7 days)
    cutoff = time.strftime("%Y-%m-%d", time.localtime(time.time() - 7 * 86400))
    usage = {k: v for k, v in usage.items() if k.split(":")[1] >= cutoff}
    _save_json(USAGE_FILE, usage)

    return True, "OK", tier


def require_tier(minimum: Tier, current: Tier) -> Tuple[bool, str]:
    """Check if current tier meets the minimum requirement for a tool."""
    if TIER_ORDER.index(current) < TIER_ORDER.index(minimum):
        return (
            False,
            f"Requires {minimum.value} tier. Current: {current.value}. "
            f"Upgrade at https://councilof.ai",
        )
    return True, "OK"


def audit_log(
    api_key: str,
    tool_name: str,
    framework: str,
    result_summary: str,
    tier: Tier,
):
    """Append to audit trail. Only Professional and Enterprise tiers generate audit logs."""
    if not TIER_LIMITS[tier]["audit_trail"]:
        return
    
    _ensure_dir()
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool": tool_name,
        "framework": framework,
        "result": result_summary[:200],
        "tier": tier.value,
        "key_prefix": (api_key or "")[:8] + "...",
    }
    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


def get_usage_stats(api_key: str = "") -> dict:
    """Get usage statistics for an API key."""
    usage = _load_json(USAGE_FILE)
    tier = get_tier_from_api_key(api_key)
    limits = TIER_LIMITS[tier]
    
    key_hash = hashlib.sha256((api_key or "anon").encode()).hexdigest()[:12]
    today = time.strftime("%Y-%m-%d")
    day_key = f"{key_hash}:{today}"
    
    return {
        "tier": tier.value,
        "calls_today": usage.get(day_key, 0),
        "limit": limits["calls_per_day"],
        "remaining": max(0, limits["calls_per_day"] - usage.get(day_key, 0))
            if limits["calls_per_day"] != -1 else "unlimited",
        "audit_trail": limits["audit_trail"],
    }


# CLI for key management
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python auth_middleware.py generate <tier> <customer_name>")
        print("  python auth_middleware.py list")
        print("  python auth_middleware.py stats <api_key>")
        print(f"\nTiers: {', '.join(t.value for t in Tier)}")
        sys.exit(0)
    
    cmd = sys.argv[1]
    
    if cmd == "generate":
        tier = Tier(sys.argv[2])
        name = sys.argv[3]
        key = generate_api_key(tier, name)
        print(f"Generated key: {key}")
        print(f"Tier: {tier.value}")
        print(f"Customer: {name}")
    
    elif cmd == "list":
        keys = _load_json(KEYS_FILE)
        for k, v in keys.items():
            status = "active" if v.get("active", True) else "disabled"
            print(f"  {k[:20]}... | {v['tier']:15} | {v['customer']:20} | {status}")
    
    elif cmd == "stats":
        key = sys.argv[2]
        stats = get_usage_stats(key)
        print(json.dumps(stats, indent=2))
