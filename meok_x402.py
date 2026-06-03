"""MEOK x402 — per-call monetization for high-value MCP tools.

A second revenue rail that stacks on the existing Stripe subscriptions: it bills
*autonomous agents* per call in USDC, and (on first settled payment) auto-lists the
endpoint in the x402 Bazaar / AWS AgentCore. The flagships stay free/MIT for human
self-host; this only activates when a deployment opts in.

Design — correct x402-over-MCP semantics (NOT HTTP 402, which MCP clients can't read):
the payment travels in the MCP request `_meta["x402/payment"]`, and the challenge is
returned to the client describing price + how to pay (mirrors the x402 SDK's
`create_payment_wrapper`, bridged onto FastMCP's `@mcp.tool()` convention).

OFF by default: with `X402_ENABLED` unset, `@paywalled(...)` returns the function
UNCHANGED — zero overhead, zero behaviour change, so existing builds/tests are unaffected.

Turn on per-deployment via env:
    X402_ENABLED=1
    X402_PAY_TO=0xYourBaseWallet      # Coinbase CDP receiving address  ← NEEDS NICK
    X402_PRICE=$0.10                  # default price per call (override per-tool)
    X402_NETWORK=eip155:8453          # Base mainnet (84532 = Base Sepolia testnet)
    X402_ASSET=0x833589fCD6...        # optional; defaults to USDC for the network
    X402_FACILITATOR_URL=https://x402.org/facilitator   # optional override

Usage in a flagship `server.py` (apply only to high-value tools; leave quick_scan /
deadline_check FREE as top-of-funnel):

    from meok_x402 import paywalled
    from mcp.server.fastmcp import Context

    @mcp.tool()
    @paywalled(price="$0.25")   # COST WARNING surfaced in the tool description (AWS convention)
    def audit_report(system: str, ctx: Context) -> dict:
        ...
"""
from __future__ import annotations

import contextvars
import functools
import json
import logging
import os
from typing import Any, Callable, Optional

log = logging.getLogger("meok.x402")

# True while the wrapped tool body runs under a VERIFIED x402 payment. Flagship
# rate-limiters consult this so paying agents bypass the free-tier daily cap.
_paid_call: contextvars.ContextVar[bool] = contextvars.ContextVar("meok_x402_paid", default=False)


def is_paid_call() -> bool:
    """True if the current tool invocation is backed by a verified x402 payment."""
    return _paid_call.get()

# x402/payment carries the signed payment; x402/payment-response carries the challenge.
PAYMENT_META_KEY = "x402/payment"
PAYMENT_RESPONSE_META_KEY = "x402/payment-response"

# Canonical USDC (6-decimal) per network, used when X402_ASSET is unset.
_USDC = {
    "eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",   # Base mainnet
    "eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",  # Base Sepolia
}
_USDC_DECIMALS = 6


def enabled() -> bool:
    """True only when the deployment has explicitly opted into x402 billing."""
    return os.environ.get("X402_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")


def _network() -> str:
    return os.environ.get("X402_NETWORK", "eip155:8453")


def _asset(network: str) -> str:
    return os.environ.get("X402_ASSET") or _USDC.get(network, _USDC["eip155:8453"])


def _price_to_atomic(price: str) -> str:
    """'$0.10' -> '100000' (USDC has 6 decimals). Accepts bare numbers too."""
    dollars = float(str(price).strip().lstrip("$"))
    return str(int(round(dollars * (10 ** _USDC_DECIMALS))))


def _accepts(price: str) -> list:
    """The PaymentRequirements list for this deployment's wallet/network/price."""
    from x402.schemas import PaymentRequirements

    network = _network()
    return [
        PaymentRequirements(
            scheme="exact",
            network=network,
            asset=_asset(network),
            amount=_price_to_atomic(price),
            pay_to=os.environ["X402_PAY_TO"],
            max_timeout_seconds=int(os.environ.get("X402_TIMEOUT", "300")),
        )
    ]


def build_challenge(tool_name: str, price: str, error: str = "Payment required") -> dict:
    """Return the spec-correct x402 PaymentRequired challenge as wire JSON.

    Pure/deterministic — no chain calls, no wallet — so it is unit-testable and is
    also what an x402-aware MCP client reads to construct its payment.
    """
    from x402 import ResourceInfo
    from x402.schemas import PaymentRequired

    challenge = PaymentRequired(
        x402_version=1,
        error=error,
        resource=ResourceInfo(url=f"mcp://tool/{tool_name}", service_name="meok-compliance-gateway"),
        accepts=_accepts(price),
    )
    return challenge.model_dump(by_alias=True)


# ── facilitator (verify/settle) is lazy: only imported once a payment is presented,
#    so the EVM/web3 dependency tree never loads for the free-discovery path. ──────────
_server = None


def _resource_server():
    global _server
    if _server is None:
        from x402 import x402ResourceServerSync
        from x402.http import HTTPFacilitatorClientSync

        url = os.environ.get("X402_FACILITATOR_URL")
        facilitator = HTTPFacilitatorClientSync({"url": url}) if url else HTTPFacilitatorClientSync()
        _server = x402ResourceServerSync(facilitator)
    return _server


def _extract_meta(ctx: Any) -> dict:
    """Best-effort read of the MCP request `_meta` from a FastMCP Context."""
    for path in (
        lambda: ctx.request_context.request.params.meta,
        lambda: ctx.request_context.meta,
        lambda: ctx.request_context.request.params.model_extra.get("_meta"),
    ):
        try:
            meta = path()
            if meta:
                return dict(meta)
        except Exception:
            continue
    return {}


def _find_ctx(args: tuple, kwargs: dict):
    if "ctx" in kwargs:
        return kwargs["ctx"]
    for v in list(kwargs.values()) + list(args):
        # duck-type a FastMCP Context without importing it at module load
        if hasattr(v, "request_context"):
            return v
    return None


def _unpaid(tool_name: str, price: str, error: str = "Payment required"):
    """Emit the challenge in x402's canonical MCP shape: an isError result whose text
    is the PaymentRequired JSON (mirrors the SDK's create_payment_wrapper). Raising
    ToolError keeps FastMCP's typed-output validation out of the way for `-> str` tools.
    """
    envelope = {PAYMENT_RESPONSE_META_KEY: build_challenge(tool_name, price, error)}
    try:
        from mcp.server.fastmcp.exceptions import ToolError
    except ImportError:  # non-FastMCP harness (e.g. unit tests without mcp)
        return envelope
    raise ToolError(json.dumps(envelope))


def paywalled(price: Optional[str] = None, *, tool_name: Optional[str] = None) -> Callable:
    """Decorator for a FastMCP tool. No-op unless X402_ENABLED.

    When enabled, the decorated tool must be able to see the request `_meta` — declare a
    `ctx: Context` parameter so FastMCP injects it. If no valid payment is present the
    tool returns the x402 challenge (price + pay-to); otherwise the call runs and the
    payment is verified/settled via the facilitator.
    """
    price = price or os.environ.get("X402_PRICE", "$0.10")

    def deco(fn: Callable) -> Callable:
        if not enabled():
            return fn  # transparent passthrough — free self-host unaffected
        name = tool_name or fn.__name__

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            ctx = _find_ctx(args, kwargs)
            payment = _extract_meta(ctx).get(PAYMENT_META_KEY)
            if not payment:
                return _unpaid(name, price)
            try:
                server = _resource_server()
                reqs = server.find_matching_requirements(_accepts(price), payment)
                verify = server.verify_payment(payment, reqs)
                if not getattr(verify, "is_valid", False):
                    return _unpaid(name, price, getattr(verify, "invalid_reason", None) or "verification failed")
                token = _paid_call.set(True)  # lets flagship rate-limiters waive the free-tier cap
                try:
                    result = fn(*args, **kwargs)
                finally:
                    _paid_call.reset(token)
                try:
                    server.settle_payment(payment, reqs)  # best-effort settle
                except Exception as exc:  # noqa: BLE001
                    log.warning("x402 settle failed for %s: %r", name, exc)
                return result
            except Exception as exc:  # noqa: BLE001 — never let billing break the tool
                if type(exc).__name__ == "ToolError":
                    raise  # the challenge itself — must reach the client, not fail open
                log.error("x402 path errored for %s, failing OPEN (serving the call): %r", name, exc)
                return fn(*args, **kwargs)

        return wrapper

    return deco
