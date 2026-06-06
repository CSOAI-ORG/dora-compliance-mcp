"""Tests for meok_x402 — runnable without a wallet/chain (verify/settle is excluded).

    pip install x402 && python tests/test_x402.py     # exits non-zero on failure

Covers the two deterministic, money-free paths:
  - DISABLED  → @paywalled is a transparent no-op (free self-host unaffected)
  - ENABLED   → correct x402 challenge JSON + unpaid calls are gated before the tool runs
The verify/settle path needs a funded wallet + facilitator and is exercised in staging.
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_disabled_is_noop():
    os.environ.pop("X402_ENABLED", None)
    import meok_x402
    importlib.reload(meok_x402)

    def my_tool(x):
        return {"ok": x}

    assert meok_x402.paywalled(price="$0.25")(my_tool) is my_tool, "disabled must be a passthrough"


def _enable():
    os.environ.update(
        X402_ENABLED="1",
        X402_PAY_TO="0x000000000000000000000000000000000000dEaD",
        X402_NETWORK="eip155:8453",
    )
    import meok_x402
    importlib.reload(meok_x402)
    return meok_x402


def test_challenge_shape_and_price_math():
    m = _enable()
    ch = m.build_challenge("audit_report", "$0.25")
    acc = ch["accepts"][0]
    assert ch["x402Version"] == 1
    assert ch["resource"]["url"] == "mcp://tool/audit_report"
    assert acc["scheme"] == "exact" and acc["network"] == "eip155:8453"
    assert acc["amount"] == "250000", acc["amount"]            # $0.25 → 250000 atomic USDC (6dp)
    assert acc["payTo"].endswith("dEaD")
    assert acc["asset"].lower().startswith("0x833589fc")        # USDC on Base mainnet
    assert m._price_to_atomic("$1") == "1000000"
    assert m._price_to_atomic("0.005") == "5000"


def test_unpaid_call_is_gated():
    import json

    m = _enable()

    class _P:
        meta = {}            # no x402/payment present

    class _R:
        params = _P()

    class _RC:
        request = _R()

    class _Ctx:
        request_context = _RC()

    ran = {"v": False}

    def audit_report(system, ctx):
        ran["v"] = True
        return {"ran": True}

    # Canonical x402-MCP challenge = isError result with the PaymentRequired JSON as text
    # (mirrors the SDK's create_payment_wrapper) — FastMCP surfaces ToolError exactly so.
    from mcp.server.fastmcp.exceptions import ToolError

    try:
        m.paywalled(price="$0.25")(audit_report)("acme", ctx=_Ctx())
        raise AssertionError("unpaid call must raise the challenge ToolError")
    except ToolError as exc:
        envelope = json.loads(str(exc))
        assert m.PAYMENT_RESPONSE_META_KEY in envelope
        assert envelope[m.PAYMENT_RESPONSE_META_KEY]["accepts"][0]["amount"] == "250000"
    assert ran["v"] is False, "tool body must NOT run when unpaid"
    assert m.is_paid_call() is False


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS  {name}")
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print(f"FAIL  {name}: {exc!r}", file=sys.stderr)
    sys.exit(1 if failures else 0)
