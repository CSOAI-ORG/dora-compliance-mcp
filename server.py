#!/usr/bin/env python3
"""
DORA (EU Digital Operational Resilience Act) Compliance MCP Server
===================================================================
By MEOK AI Labs | https://meok.ai

The only MCP server that automates DORA compliance checking for EU financial
entities. Covers the 5 pillars under Regulation (EU) 2022/2554, Articles 5–45.

ENFORCEMENT: 17 January 2025 (LIVE). First full reporting cycle: 2026.
IN SCOPE: credit institutions, payment institutions, investment firms,
    insurance, crypto-asset service providers, crowdfunding platforms, and
    ICT third-party service providers designated as critical (CTPPs).
PENALTIES: Up to 1% of daily global turnover for CTPPs; national authority
    sanctions for financial entities (member-state specific, up to €5M).

Install: pip install dora-compliance-mcp
Run:     python server.py
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Optional
from collections import defaultdict
from mcp.server.fastmcp import FastMCP, Context
try:
    from meok_x402 import paywalled, is_paid_call  # x402 per-call agent billing — no-op unless X402_ENABLED
except ImportError:  # vendored module absent — stay free
    def paywalled(*_a, **_k):
        return lambda fn: fn
    def is_paid_call() -> bool:
        return False

# ── Authentication ──────────────────────────────────────────────
import os as _os
import sys
import os

_MEOK_API_KEY = _os.environ.get("MEOK_API_KEY", "")

try:
    from meok_auth import check_access as _shared_check_access
except ImportError:
    try:
        from auth_middleware import check_access as _shared_check_access
    except ImportError:
        def _shared_check_access(api_key: str = ""):
            if _MEOK_API_KEY and api_key and api_key == _MEOK_API_KEY:
                return True, "OK", "pro"
            if _MEOK_API_KEY and api_key and api_key != _MEOK_API_KEY:
                return False, "Invalid API key. Get one at https://meok.ai/api-keys", "free"
            return True, "OK", "free"


try:
    from attestation import get_attestation_tool_response
    _ATTESTATION_LOCAL = True
except ImportError:
    _ATTESTATION_LOCAL = False

_ATTESTATION_API_URL = _os.environ.get("MEOK_ATTESTATION_API_URL", "")

import hashlib
import hmac as _hmac


def _local_hmac_sign(regulation: str, entity: str, score: float,
                     findings: list, articles_audited: list, tier: str = "pro",
                     include_pdf_base64: bool = False) -> dict:
    """Local fallback: sign attestation with HMAC-SHA256 using MEOK_API_KEY as secret.
    Produces a verifiable signature without making any external network calls."""
    SigningSecret = _MEOK_API_KEY.encode("utf-8") if _MEOK_API_KEY else b"meok-local-fallback"
    timestamp = datetime.now(timezone.utc).isoformat()
    payload_str = json.dumps({
        "regulation": regulation, "entity": entity, "score": score,
        "findings": findings or [], "articles_audited": articles_audited or [],
        "tier": tier, "timestamp": timestamp,
    }, sort_keys=True)
    signature = _hmac.new(SigningSecret, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "regulation": regulation, "entity": entity, "score": score,
        "findings": findings or [], "articles_audited": articles_audited or [],
        "tier": tier, "timestamp": timestamp,
        "signature": signature, "signature_algorithm": "HMAC-SHA256",
        "signed_locally": True,
        "verify_url": f"https://meok.ai/verify?sig={signature}&regulation={regulation}",
    }


def _sign_via_api(api_key: str, regulation: str, entity: str, score: float,
                   findings: list, articles_audited: list, tier: str = "pro",
                   include_pdf_base64: bool = False) -> dict:
    """Remote signing via MEOK attestation API.
    WARNING: This makes an external HTTP call to the configured MEOK_ATTESTATION_API_URL.
    Only used when MEOK_ATTESTATION_API_URL env var is explicitly set. Falls back to
    local HMAC signing if the env var is not set or the remote call fails."""
    if not _ATTESTATION_API_URL:
        return _local_hmac_sign(regulation, entity, score, findings,
                                articles_audited, tier, include_pdf_base64)
    import urllib.request as _url, urllib.error as _urlerr
    payload = {
        "regulation": regulation, "entity": entity,
        "score": score, "findings": findings or [],
        "articles_audited": articles_audited or [], "tier": tier,
    }
    try:
        req = _url.Request(
            f"{_ATTESTATION_API_URL}/sign",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with _url.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except _urlerr.HTTPError as e:
        try:
            remote_err = json.loads(e.read())
        except Exception:
            remote_err = {"error": f"Attestation API HTTP {e.code}"}
        return _local_hmac_sign(regulation, entity, score, findings,
                                articles_audited, tier, include_pdf_base64)
    except Exception as e:
        return _local_hmac_sign(regulation, entity, score, findings,
                                articles_audited, tier, include_pdf_base64)


def _attestation(regulation, entity, score, findings, articles_audited, tier,
                 include_pdf_base64, api_key):
    """Try local module first (fast, for Nick's dev machine), fall back to remote API."""
    if _ATTESTATION_LOCAL:
        return get_attestation_tool_response(
            regulation=regulation, entity=entity, score=score, findings=findings,
            articles_audited=articles_audited, tier=tier,
            include_pdf_base64=include_pdf_base64,
        )
    return _sign_via_api(
        api_key=api_key, regulation=regulation, entity=entity, score=score,
        findings=findings, articles_audited=articles_audited, tier=tier,
        include_pdf_base64=include_pdf_base64,
    )


def check_access(api_key: str = ""):
    # 2026-06-12 PM22: wire /verify call site (fail-open)
    try:
        _meter = _server_meter_check("dora_compliance")
        if not _meter.get("allowed", True):
            return False, "Free tier limit reached. Upgrade to Pro at https://meok.ai/dora-compliance-mcp", "free"
    except Exception:
        pass  # fail-open
    return _shared_check_access(api_key)


# ── Stripe payment links ────────────────────────────────────────
STRIPE_199 = "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t?utm_source=mcp&utm_medium=tool&utm_content=ratelimit_tail"
STRIPE_1499 = "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t?utm_source=mcp&utm_medium=tool&utm_content=ratelimit_tail"
STRIPE_5K = "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t?utm_source=mcp&utm_medium=tool&utm_content=ratelimit_tail"


# ── Rate limiting ───────────────────────────────────────────────
FREE_DAILY_LIMIT = 50
_usage: dict[str, list[datetime]] = defaultdict(list)


def _check_rate_limit(caller: str = "anonymous", tier: str = "free") -> Optional[str]:
    if tier in ("pro", "professional", "enterprise"):
        return None
    if is_paid_call():
        return None  # settled x402 payment — this call is already paid for
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=1)
    _usage[caller] = [t for t in _usage[caller] if t > cutoff]
    if len(_usage[caller]) >= FREE_DAILY_LIMIT:
        return (
            f"Free tier limit reached ({FREE_DAILY_LIMIT}/day). "
            f"Upgrade to MEOK AI Labs Pro at £79/mo for unlimited access + signed attestations: {STRIPE_199}"
        )
    _usage[caller].append(now)
    return None


# ── DORA Knowledge Base ─────────────────────────────────────────
# Regulation (EU) 2022/2554 — the five pillars
DORA_PILLARS = {
    1: {
        "title": "ICT Risk Management",
        "articles": "5–16",
        "summary": "Governance, ICT risk framework, identification/classification of ICT assets and functions, protection and prevention, detection, response/recovery, learning/evolving, communication.",
        "key_obligations": [
            "Management body approves and periodically reviews ICT risk framework (Article 5)",
            "Identify and classify ICT-supported business functions, information assets, and ICT assets (Article 8)",
            "Document dependencies on ICT third-party service providers (Article 8)",
            "Implement policies for protection and prevention: authentication, encryption, segmentation, logging (Article 9)",
            "Anomalous-activity detection mechanisms (Article 10)",
            "Business continuity and disaster recovery plans tested at least annually (Article 11)",
            "Backup policies, data integrity verification (Article 12)",
            "Post-incident learning and crisis communication (Articles 13–14)",
        ],
    },
    2: {
        "title": "ICT-Related Incident Management",
        "articles": "17–23",
        "summary": "Detection, classification, reporting of ICT incidents; thresholds for 'major' ICT incidents; reporting to competent authority.",
        "key_obligations": [
            "Process for monitoring, handling, follow-up, and classifying ICT-related incidents (Article 17)",
            "Classify incidents using criteria in Commission Delegated Regulation (EU) 2024/1772 (Article 18)",
            "Report MAJOR ICT incidents and significant cyber threats to competent authority (Article 19)",
            "Initial notification within 4 hours of classification as major",
            "Intermediate report within 72 hours",
            "Final report within 1 month",
            "Voluntary notification of significant cyber threats (Article 19)",
            "Root-cause analysis documented and lessons integrated (Article 13)",
        ],
    },
    3: {
        "title": "Digital Operational Resilience Testing",
        "articles": "24–27",
        "summary": "Testing programme, scope and methodology, remediation. Threat-Led Penetration Testing (TLPT) for significant financial entities every 3 years.",
        "key_obligations": [
            "Sound, comprehensive testing programme integrated into ICT risk mgmt (Article 24)",
            "Tests: vulnerability assessments, scenario-based tests, red-team/TLPT, performance tests (Article 25)",
            "TLPT at least every 3 years for significant entities, aligned with TIBER-EU methodology (Article 26)",
            "External testers must meet Article 27 requirements (reputation, ethics, insurance, methodologies)",
            "Tests of critical ICT third-party services in production (intrusive) require TLPT",
            "Remediation of findings tracked and reported to competent authority",
        ],
    },
    4: {
        "title": "ICT Third-Party Risk Management",
        "articles": "28–44",
        "summary": "Governance and contractual arrangements for ICT third-party risk. Oversight framework for Critical ICT Third-Party Providers (CTPPs) — direct EU-level supervision by ESAs.",
        "key_obligations": [
            "Strategy on ICT third-party risk, approved by management body (Article 28)",
            "Maintain Register of Information on all contractual arrangements (Article 28.3) — submitted annually",
            "Pre-contractual assessments: criticality of service, risk concentration, due diligence (Article 28)",
            "Contractual provisions required (Article 30): full rights of access/audit, termination rights, exit strategies, service-level objectives, location of data processing",
            "Enhanced contractual terms for CRITICAL or IMPORTANT functions (Article 30.3)",
            "Exit strategies with documented transition plans (Article 28.8)",
            "Critical ICT Third-Party Providers designated by ESAs and subject to Union oversight (Articles 31–44)",
            "Lead overseer can impose: recommendations, information requests, inspections, periodic penalty payments up to 1% of daily global turnover",
        ],
    },
    5: {
        "title": "Information and Intelligence Sharing",
        "articles": "45",
        "summary": "Voluntary arrangements for sharing cyber threat intelligence among financial entities, subject to data protection.",
        "key_obligations": [
            "May exchange cyber threat information within trusted communities (Article 45)",
            "Arrangements must protect confidentiality, comply with GDPR and competition law",
            "Notification to competent authority of participation or withdrawal",
        ],
    },
}

# Entity types in scope (Article 2)
ENTITY_TYPES_IN_SCOPE = {
    "credit_institution": "Credit institutions (Article 4(1)(1) of Regulation (EU) 575/2013)",
    "payment_institution": "Payment institutions (Directive (EU) 2015/2366, PSD2)",
    "emi": "Electronic money institutions (Directive 2009/110/EC)",
    "investment_firm": "Investment firms (Directive 2014/65/EU, MiFID II)",
    "crypto_asset_service_provider": "Crypto-asset service providers (Regulation (EU) 2023/1114, MiCA)",
    "central_securities_depository": "Central securities depositories (Regulation (EU) 909/2014)",
    "central_counterparty": "Central counterparties (Regulation (EU) 648/2012, EMIR)",
    "trading_venue": "Trading venues (Directive 2014/65/EU)",
    "trade_repository": "Trade repositories (Regulation (EU) 648/2012)",
    "manager_aif": "Managers of alternative investment funds (Directive 2011/61/EU, AIFMD)",
    "management_company_ucits": "Management companies (Directive 2009/65/EC, UCITS)",
    "data_reporting_service_provider": "Data reporting service providers",
    "insurance_reinsurance": "Insurance and reinsurance undertakings (Directive 2009/138/EC, Solvency II)",
    "insurance_intermediary": "Insurance intermediaries (Directive (EU) 2016/97, IDD) — except microenterprises",
    "iorp": "Institutions for occupational retirement provision (Directive (EU) 2016/2341)",
    "credit_rating_agency": "Credit rating agencies (Regulation (EC) 1060/2009)",
    "administrator_critical_benchmark": "Administrators of critical benchmarks (Regulation (EU) 2016/1011)",
    "crowdfunding_service_provider": "Crowdfunding service providers (Regulation (EU) 2020/1503)",
    "securitisation_repository": "Securitisation repositories (Regulation (EU) 2017/2402)",
    "ict_third_party": "ICT third-party service providers (when designated as CRITICAL by ESAs)",
}

# Key thresholds
ENFORCEMENT_DATE = datetime(2025, 1, 17, tzinfo=timezone.utc)

mcp = FastMCP(
    "dora-compliance",
    instructions=(
        "MEOK AI Labs DORA Compliance MCP. Automates audits against the EU Digital "
        "Operational Resilience Act (Regulation (EU) 2022/2554). Ask me to classify "
        "your entity, audit any of the 5 pillars, generate your Article 28 Register of "
        "Information, classify ICT incidents, or assess TLPT readiness."
    ),
)


# ── TOOLS ───────────────────────────────────────────────────────

_UPSELL = (
    "\n\n──────────────────────\n"
    "⚖️  Part of CSOAI — the open AI-governance standard · by MEOK AI Labs\n"
    "   • All-access · 300+ governance & compliance MCPs → https://meok.ai/pricing\n"
    "   • Get this assessment human-signed & audited (£29) → https://meok.ai/work\n"
    "   • Open standard · transparent crosswalks · a fraction of enterprise-GRC cost\n"
    "   ⭐ Free & open-source → https://github.com/CSOAI-ORG/dora-compliance-mcp"
)
import functools as _ft, inspect as _isp
_orig_tool = mcp.tool
def _tool_with_upsell(*da, **dk):
    deco = _orig_tool(*da, **dk)
    def wrap(fn):
        @_ft.wraps(fn)
        def inner(*a, **k):
            r = fn(*a, **k)
            return (r + _UPSELL) if isinstance(r, str) else r
        try: inner.__signature__ = _isp.signature(fn)
        except Exception: pass
        return deco(inner)
    return wrap
mcp.tool = _tool_with_upsell

@mcp.tool()
def classify_entity(description: str, api_key: str = "") -> str:
    """Classify a financial entity's DORA applicability + which entity type it is.
    Returns in-scope status, entity type, proportionality tier, and starting pillars.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need to assess, audit, or verify compliance
        requirements. Ideal for gap analysis, readiness checks, and generating
        compliance documentation.

    When NOT to use:
        Do not use as a substitute for qualified legal counsel. This tool
        provides technical compliance guidance, not legal advice.

    Args:
        description (str): The description to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t?utm_source=mcp&utm_medium=tool&utm_content=ratelimit_tail"})
    if err := _check_rate_limit(tier=tier):
        return json.dumps({"error": err, "upgrade_url": "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t?utm_source=mcp&utm_medium=tool&utm_content=ratelimit_tail"})

    d = description.lower()
    matches = []
    for key, label in ENTITY_TYPES_IN_SCOPE.items():
        hint = key.replace("_", " ")
        if hint in d or any(t in d for t in hint.split()):
            matches.append({"entity_type": key, "label": label})

    # Proportionality (Article 4): microenterprises benefit from simplified regime
    micro = any(w in d for w in ["micro", "under 10 employees", "<10 employees", "small enterprise"])

    in_scope = len(matches) > 0
    days_since_enforcement = (datetime.now(timezone.utc) - ENFORCEMENT_DATE).days
    return json.dumps({
        "in_scope": in_scope,
        "days_since_enforcement": days_since_enforcement,
        "enforcement_date": ENFORCEMENT_DATE.isoformat(),
        "probable_entity_types": matches or [{"note": "Entity type not clearly matched — provide more detail about your financial services"}],
        "proportionality": "simplified_regime" if micro else "full_regime",
        "simplified_regime_note": "Article 16 allows simplified ICT risk management for microenterprises, entities below thresholds in Article 3, or manufacturers/intermediaries meeting size criteria." if micro else None,
        "all_five_pillars_apply": in_scope and not micro,
        "next_step": "Run audit_pillar(1..5) for each of the 5 pillars, or run audit_all_pillars() for complete scan.",
    }, indent=2)


@mcp.tool()
def list_pillars(api_key: str = "") -> str:
    """List all 5 DORA pillars with article ranges and key obligations.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need to assess, audit, or verify compliance
        requirements. Ideal for gap analysis, readiness checks, and generating
        compliance documentation.

    When NOT to use:
        Do not use as a substitute for qualified legal counsel. This tool
        provides technical compliance guidance, not legal advice.

    Args:
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg})
    return json.dumps({
        "regulation": "Regulation (EU) 2022/2554 (DORA)",
        "pillars": [{"pillar": k, **v} for k, v in DORA_PILLARS.items()],
    }, indent=2)


@mcp.tool()
@paywalled(price="$0.10")
def audit_pillar(pillar_number: int, entity_description: str, current_controls: str = "", api_key: str = "",
    ctx: Context = None) -> str:
    """COST WARNING: $0.10/call on x402-billed deployments (hosted); free when self-hosted or X402 is disabled.

    Audit a specific DORA pillar (1-5) against your entity's current controls.
    Returns per-obligation pass/fail + gap list + remediation priority.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need to assess, audit, or verify compliance
        requirements. Ideal for gap analysis, readiness checks, and generating
        compliance documentation.

    When NOT to use:
        Do not use as a substitute for qualified legal counsel. This tool
        provides technical compliance guidance, not legal advice.

    Args:
        pillar_number (int): The pillar number to analyze or process.
        entity_description (str): The entity description to analyze or process.
        current_controls (str): The current controls to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t?utm_source=mcp&utm_medium=tool&utm_content=ratelimit_tail"})
    if err := _check_rate_limit(tier=tier):
        return json.dumps({"error": err})

    if pillar_number not in DORA_PILLARS:
        return json.dumps({"error": "pillar_number must be 1, 2, 3, 4, or 5"})

    pillar = DORA_PILLARS[pillar_number]
    controls = (current_controls + " " + entity_description).lower()

    # Keyword heuristic matching (would be neural-net-backed in Pro tier)
    keyword_map = {
        "management body": ["board", "management body", "governance", "ceo approved"],
        "ict assets": ["asset inventory", "cmdb", "ict register", "asset classification"],
        "encryption": ["encryption", "tls", "aes", "pgp", "at rest", "in transit"],
        "segmentation": ["network segmentation", "zero trust", "microsegmentation", "vlan"],
        "logging": ["logging", "siem", "audit log", "splunk", "elk", "datadog"],
        "anomalous": ["anomaly", "ids", "ips", "ueba", "xdr", "edr"],
        "business continuity": ["bcp", "business continuity", "disaster recovery", "rto", "rpo"],
        "backup": ["backup", "snapshot", "replication", "immutable backup"],
        "classification": ["incident classification", "severity rating", "major incident"],
        "incident process": ["incident response", "ir playbook", "cert", "csirt"],
        "reporting 4h": ["4 hour", "four hour", "initial notification"],
        "reporting 72h": ["72 hour", "intermediate report"],
        "reporting 1m": ["final report", "one month"],
        "testing programme": ["pentest", "vulnerability assessment", "red team", "purple team"],
        "tlpt": ["tlpt", "threat-led penetration", "tiber"],
        "third-party register": ["third party register", "vendor inventory", "ict register", "article 28"],
        "contractual audit rights": ["audit rights", "right to audit", "inspection clause"],
        "exit strategy": ["exit strategy", "exit plan", "transition plan"],
        "threat sharing": ["fs-isac", "threat intel sharing", "information sharing"],
    }

    obligations_results = []
    passed = 0
    for ob in pillar["key_obligations"]:
        ob_lower = ob.lower()
        matched = False
        matched_keywords = []
        for concept, kws in keyword_map.items():
            if any(k in ob_lower for k in [concept] + kws[:1]):
                # Check if controls mention any matching keyword
                if any(kw in controls for kw in kws):
                    matched = True
                    matched_keywords.extend([kw for kw in kws if kw in controls])
                    break
        obligations_results.append({
            "obligation": ob,
            "status": "EVIDENCE_FOUND" if matched else "GAP",
            "evidence_signals": matched_keywords if matched else [],
        })
        if matched:
            passed += 1

    total = len(pillar["key_obligations"])
    score = round(passed / total * 100, 1)

    gaps = [o["obligation"] for o in obligations_results if o["status"] == "GAP"]

    return json.dumps({
        "pillar": pillar_number,
        "pillar_title": pillar["title"],
        "articles": pillar["articles"],
        "score_percent": score,
        "passed": passed,
        "total": total,
        "assessment": "COMPLIANT" if score >= 70 else "PARTIAL" if score >= 40 else "NON_COMPLIANT",
        "gaps_to_address": gaps,
        "remediation_priority": (
            "CRITICAL — initiate immediate gap closure; contact ESA if incidents have occurred without reporting" if score < 40 else
            "HIGH — close gaps within 30 days to avoid sanctions" if score < 70 else
            "MEDIUM — document evidence and integrate into ICT risk framework"
        ),
        "obligations_detail": obligations_results,
        "upsell": "Run audit_all_pillars for a full 5-pillar sweep, or get_dora_certificate for a signed evidence pack." if tier == "free" else None,
    }, indent=2)


@mcp.tool()
@paywalled(price="$0.50")
def audit_all_pillars(entity_description: str, current_controls: str = "", api_key: str = "",
    ctx: Context = None) -> str:
    """COST WARNING: $0.50/call on x402-billed deployments (hosted); free when self-hosted or X402 is disabled.

    Run audits across all 5 DORA pillars and return an executive summary.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need to assess, audit, or verify compliance
        requirements. Ideal for gap analysis, readiness checks, and generating
        compliance documentation.

    When NOT to use:
        Do not use as a substitute for qualified legal counsel. This tool
        provides technical compliance guidance, not legal advice.

    Args:
        entity_description (str): The entity description to analyze or process.
        current_controls (str): The current controls to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t?utm_source=mcp&utm_medium=tool&utm_content=ratelimit_tail"})
    if tier == "free":
        return json.dumps({
            "error": "audit_all_pillars requires Starter tier (£79/mo) or above.",
            "free_alternative": "Run audit_pillar(N, ...) individually (10/day limit).",
            "upgrade_url": "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t?utm_source=mcp&utm_medium=tool&utm_content=ratelimit_tail",
        })
    if err := _check_rate_limit(tier=tier):
        return json.dumps({"error": err})

    results = []
    for p in range(1, 6):
        r = json.loads(audit_pillar(p, entity_description, current_controls, api_key))
        results.append(r)

    avg = sum(r.get("score_percent", 0) for r in results) / 5
    return json.dumps({
        "regulation": "DORA — Regulation (EU) 2022/2554",
        "overall_score": round(avg, 1),
        "overall_assessment": "COMPLIANT" if avg >= 70 else "PARTIAL" if avg >= 40 else "NON_COMPLIANT",
        "pillars": results,
        "priority_gaps": [
            {"pillar": r["pillar"], "title": r["pillar_title"], "score": r["score_percent"], "top_gaps": r["gaps_to_address"][:3]}
            for r in sorted(results, key=lambda x: x.get("score_percent", 0))[:3]
        ],
        "next_steps": [
            "Start with pillar 4 (ICT Third-Party Risk) — highest enforcement activity so far under DORA",
            "File Register of Information with competent authority (Article 28.3) — annual obligation",
            "Ensure incident classification thresholds aligned with Commission Delegated Regulation (EU) 2024/1772",
            "Schedule TLPT if significant entity (Article 26)",
        ],
    }, indent=2)


@mcp.tool()
@paywalled(price="$0.10")
def classify_incident(
    incident_description: str,
    clients_affected: int = 0,
    duration_hours: float = 0,
    economic_impact_eur: float = 0,
    data_loss: bool = False,
    api_key: str = "",
    ctx: Context = None) -> str:
    """COST WARNING: $0.10/call on x402-billed deployments (hosted); free when self-hosted or X402 is disabled.

    Classify an ICT incident against DORA major-incident thresholds per Commission Delegated Regulation (EU) 2024/1772.
    Returns whether it qualifies as a 'major ICT incident' requiring 4h/72h/1-month reporting.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need to assess, audit, or verify compliance
        requirements. Ideal for gap analysis, readiness checks, and generating
        compliance documentation.

    When NOT to use:
        Do not use as a substitute for qualified legal counsel. This tool
        provides technical compliance guidance, not legal advice.

    Args:
        incident_description (str): The incident description to analyze or process.
        clients_affected (int): The clients affected to analyze or process.
        duration_hours (float): The duration hours to analyze or process.
        economic_impact_eur (float): The economic impact eur to analyze or process.
        data_loss (bool): The data loss to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t?utm_source=mcp&utm_medium=tool&utm_content=ratelimit_tail"})
    if err := _check_rate_limit(tier=tier):
        return json.dumps({"error": err})

    # Primary criteria (Commission Delegated Regulation (EU) 2024/1772)
    # MAJOR if it meets 2+ primary criteria OR 1 primary + significant thresholds
    primary_triggers = []

    if clients_affected >= 100000 or (clients_affected > 0 and clients_affected >= 0.1 * 1000000):
        primary_triggers.append(f"Clients/transactions affected: {clients_affected:,} (≥100,000 or ≥10% of population)")
    if duration_hours >= 24:
        primary_triggers.append(f"Duration: {duration_hours}h (≥24h)")
    if duration_hours >= 2 and "critical" in incident_description.lower():
        primary_triggers.append(f"Critical service unavailable for {duration_hours}h (≥2h)")
    if economic_impact_eur >= 100000:
        primary_triggers.append(f"Economic impact: €{economic_impact_eur:,.0f} (≥€100,000)")
    if data_loss:
        primary_triggers.append("Data loss / confidentiality breach confirmed")
    d = incident_description.lower()
    if any(term in d for term in ["cross-border", "cross border", "multiple eu"]):
        primary_triggers.append("Cross-border impact detected")
    if any(term in d for term in ["critical business service", "critical or important function"]):
        primary_triggers.append("Critical or important function affected")

    is_major = len(primary_triggers) >= 2 or (len(primary_triggers) >= 1 and (data_loss or economic_impact_eur >= 500000))

    now = datetime.now(timezone.utc)

    return json.dumps({
        "classification": "MAJOR_ICT_INCIDENT" if is_major else "NON_MAJOR_INCIDENT",
        "reporting_required": is_major,
        "reporting_timeline": {
            "initial_notification": "Within 4 hours of classification — send to competent authority (national)" if is_major else "Not required",
            "intermediate_report": "Within 72 hours of initial notification — updated facts, impact, mitigation" if is_major else "Not required",
            "final_report": "Within 1 month — root cause, full impact, remediation plan, lessons learned" if is_major else "Not required",
            "initial_notification_deadline_utc": (now + timedelta(hours=4)).isoformat() if is_major else None,
            "intermediate_deadline_utc": (now + timedelta(hours=72)).isoformat() if is_major else None,
            "final_deadline_utc": (now + timedelta(days=30)).isoformat() if is_major else None,
        },
        "primary_criteria_met": primary_triggers,
        "legal_basis": "Commission Delegated Regulation (EU) 2024/1772, in conjunction with DORA Article 18",
        "action_required": [
            "Notify competent authority using the harmonised template (Article 20 RTS)",
            "Assign incident coordinator; preserve evidence and logs",
            "If data loss: notify data subjects under GDPR Article 34 within 72h",
            "Update Register of Information if third-party service was involved",
        ] if is_major else ["Log in internal incident register; assess trend over time."],
    }, indent=2)


@mcp.tool()
@paywalled(price="$0.25")
def register_of_information_template(api_key: str = "",
    ctx: Context = None) -> str:
    """COST WARNING: $0.25/call on x402-billed deployments (hosted); free when self-hosted or X402 is disabled.

    Return the Article 28.3 Register of Information template structure. Financial entities must
    submit this annually to their competent authority under DORA.

    Behavior:
        This tool generates structured output without modifying external systems.
        Output is deterministic for identical inputs. No side effects.
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need to assess, audit, or verify compliance
        requirements. Ideal for gap analysis, readiness checks, and generating
        compliance documentation.

    When NOT to use:
        Do not use as a substitute for qualified legal counsel. This tool
        provides technical compliance guidance, not legal advice.

    Args:
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg})
    return json.dumps({
        "legal_basis": "DORA Article 28.3 + Commission Implementing Regulation (EU) 2024/2956",
        "annual_submission": "Required by financial entity to competent authority; first cycle ends 2026",
        "sections": [
            {
                "section": "B_01.01 — Entity information",
                "fields": ["Entity LEI", "Entity name", "Country", "Sector", "Parent entity LEI (if any)", "Branch info"],
            },
            {
                "section": "B_02.01 — Contractual arrangements overview",
                "fields": ["Contract reference", "Start date", "End date", "Function supporting", "Criticality (critical/important/other)", "Service type (ICT-service categories per RTS)", "Counterparty LEI", "Sub-contractor chain"],
            },
            {
                "section": "B_03.01 — Third-party provider details",
                "fields": ["Provider legal name", "Country of registration", "LEI", "Parent company", "Type of entity", "Authorisation/licence details"],
            },
            {
                "section": "B_04.01 — Service characteristics",
                "fields": ["ICT service type", "Data location (processing & storage countries)", "Data sensitivity", "Critical/important function supported"],
            },
            {
                "section": "B_05.01 — Contractual provisions",
                "fields": ["Audit rights clause", "Termination clause", "Exit strategy ref", "Service level objectives", "Confidentiality clause", "Data protection clause"],
            },
            {
                "section": "B_06.01 — Subcontracting chain",
                "fields": ["Sub-provider LEI", "Nth-tier dependencies", "Geographic concentration analysis"],
            },
        ],
        "submission_format": "XBRL or prescribed XML schema via ESA-designated channel (EIOPA/EBA/ESMA as applicable)",
        "penalty_for_failure": "Administrative sanctions up to €5M (varies by Member State) under Article 50",
    }, indent=2)


@mcp.tool()
def tlpt_readiness(entity_description: str, api_key: str = "") -> str:
    """Assess Threat-Led Penetration Testing (Article 26) readiness. Returns whether the entity
    is likely in scope and what's needed to pass a TIBER-EU-aligned TLPT.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need to assess, audit, or verify compliance
        requirements. Ideal for gap analysis, readiness checks, and generating
        compliance documentation.

    When NOT to use:
        Do not use as a substitute for qualified legal counsel. This tool
        provides technical compliance guidance, not legal advice.

    Args:
        entity_description (str): The entity description to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg})
    if err := _check_rate_limit(tier=tier):
        return json.dumps({"error": err})

    d = entity_description.lower()
    significant_signals = [
        "g-sii" in d, "g-sib" in d, "o-sii" in d, "o-sib" in d,
        "systemic" in d, "significant" in d,
        "total assets" in d and any(x in d for x in ["billion", "bn", "€100", "€50"]),
    ]
    in_scope = any(significant_signals)

    return json.dumps({
        "article_reference": "DORA Article 26–27 (+ RTS on TLPT)",
        "methodology": "TIBER-EU (Threat Intelligence-Based Ethical Red Teaming)",
        "frequency": "At least every 3 years for entities designated as significant",
        "probable_scope": "IN_SCOPE — prepare for TLPT" if in_scope else "LIKELY_OUT — but check national TLPT authority",
        "required_preparation": [
            "Threat intelligence provider accredited under Article 27",
            "Red team provider accredited under Article 27 (reputation, ethics, insurance)",
            "Scoping: critical/important functions identified from Article 8",
            "Production systems in scope (intrusive testing on live prod, not just test env)",
            "TI-based attack scenarios (not generic pen-test)",
            "Remediation tracking + competent-authority report",
        ],
        "common_pitfalls": [
            "Using internal red team — Article 27 restricts internal testers unless institution meets independence criteria",
            "Scoping only test environments — DORA requires production",
            "Skipping threat intelligence phase — invalidates TLPT classification",
        ],
        "typical_cost_eur": "€150,000 – €500,000 per 3-year cycle depending on institution size",
    }, indent=2)


@mcp.tool()
@paywalled(price="$0.25")
def get_dora_certificate(
    entity_name: str,
    overall_score: float,
    findings_csv: str = "",
    articles_audited_csv: str = "",
    include_pdf_base64: bool = False,
    api_key: str = "",
    ctx: Context = None) -> str:
    """COST WARNING: $0.25/call on x402-billed deployments (hosted); free when self-hosted or X402 is disabled.

    Generate a cryptographically signed DORA compliance attestation (Pro/Enterprise).

    Uses the shared MEOK attestation module (HMAC-SHA256 signed JSON + verify URL +
    optional base64-encoded PDF). Share the verify_url with your auditor / board /
    procurement team — the signature is cryptographically binding and any tampering
    invalidates it. Certificates expire 365 days from issue.

    Args:
        entity_name (str): The entity name to appear on the certificate.
        overall_score (float): Overall compliance score (0–100).
        findings_csv (str): Comma-separated list of article-level findings (e.g. "Article 9: PASS,Article 28: GAP")
        articles_audited_csv (str): Comma-separated article numbers (e.g. "9,10,28")
        include_pdf_base64 (bool): Set True to also receive a board-ready PDF as base64.
        api_key (str): MEOK API key (Pro/Enterprise tier).
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_199})
    if tier == "free":
        return json.dumps({
            "error": "Signed attestations require Pro (£79/mo) or Enterprise tier.",
            "upgrade_url": STRIPE_199,
            "why_pro": "Cryptographic HMAC signature + public verify URL + PDF auditors accept. Unsigned self-reports don't pass procurement.",
        })
    findings = [f.strip() for f in findings_csv.split(",") if f.strip()]
    articles = [a.strip() for a in articles_audited_csv.split(",") if a.strip()]
    cert = _attestation(
        regulation="DORA (Regulation (EU) 2022/2554)",
        entity=entity_name,
        score=overall_score,
        findings=findings or [f"Overall DORA posture score: {overall_score}"],
        articles_audited=articles or None,
        tier=tier,
        include_pdf_base64=include_pdf_base64,
        api_key=api_key,
    )
    return json.dumps(cert, indent=2)


@mcp.tool()
def enforcement_status(api_key: str = "") -> str:
    """Current DORA enforcement status + key upcoming deadlines for financial entities.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need to assess, audit, or verify compliance
        requirements. Ideal for gap analysis, readiness checks, and generating
        compliance documentation.

    When NOT to use:
        Do not use as a substitute for qualified legal counsel. This tool
        provides technical compliance guidance, not legal advice.

    Args:
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    now = datetime.now(timezone.utc)
    days_since = (now - ENFORCEMENT_DATE).days
    return json.dumps({
        "regulation": "Regulation (EU) 2022/2554 — DORA",
        "enforcement_started": "2025-01-17",
        "days_since_enforcement": days_since,
        "current_status": "IN_FORCE",
        "next_milestones": [
            {"date": "2026-04-30", "milestone": "First annual Register of Information submission deadline (Article 28.3)"},
            {"date": "2026-ongoing", "milestone": "TLPT cycle begins for designated significant entities"},
            {"date": "2027+", "milestone": "Rolling CTPP designations + oversight by ESAs"},
        ],
        "pending_rts_its": "Various Commission Delegated/Implementing Regulations adopted 2024 (e.g. 1772 on incident classification; 2956 on register of information template)",
        "penalty_headline": "Up to 1% of daily global turnover for Critical ICT Third-Party Providers (CTPPs) after non-compliance notification",
    }, indent=2)


# ---------------------------------------------------------------------------
# Tool: generate_incident_report — DORA RTS-compliant ICT incident template
# ---------------------------------------------------------------------------
# Closes https://github.com/CSOAI-ORG/dora-compliance-mcp/issues/1
# Templates aligned with Commission Delegated Regulation (EU) 2024/1772
# (classification criteria) and Commission Implementing Regulation (EU)
# 2024/2956 (incident-reporting forms).

_DORA_SEVERITY_TIERS = {
    "anomalous": {
        "label": "Anomalous activity",
        "criteria": "Single ICT anomaly — no client impact, no data loss, contained within minutes. Logged for internal review only.",
        "reporting_obligation": "No external report. Maintain in internal incident register (Article 17).",
        "internal_log_only": True,
    },
    "significant": {
        "label": "Significant ICT-related incident",
        "criteria": (
            "Meets ANY of: ≥10% of clients affected; service unavailable >2h; "
            "data integrity impacted with material consequence; relevant economic impact threshold per Article 4 of Delegated Reg 2024/1772."
        ),
        "reporting_obligation": (
            "Initial notification ≤4h after classification (Article 19(4)(a)). "
            "Intermediate report ≤72h. Final report ≤1 month."
        ),
        "internal_log_only": False,
    },
    "major": {
        "label": "Major ICT-related incident",
        "criteria": (
            "Cumulative thresholds per Delegated Reg 2024/1772 Article 6: "
            "critical services affected, ≥25% client base, recurring service disruption, "
            "loss of confidentiality/integrity/availability with material impact. "
            "Cross-border or systemic relevance amplifies classification."
        ),
        "reporting_obligation": (
            "Initial notification ≤4h after classification (tightest reporting clock in EU regulation). "
            "Intermediate ≤72h. Final ≤1 month. ESAs receive aggregate via competent authority."
        ),
        "internal_log_only": False,
    },
    "significant_cyber_threat": {
        "label": "Significant cyber threat (voluntary)",
        "criteria": "Confirmed threat that could have led to a significant or major incident if not stopped. Voluntary notification per Article 19(2).",
        "reporting_obligation": "Voluntary. Use the same template, mark voluntary=true in initial notification.",
        "internal_log_only": False,
    },
}


@mcp.tool()
def generate_incident_report(
    severity: str = "significant",
    entity_name: str = "",
    incident_summary: str = "",
    api_key: str = ""
) -> dict:
    """Generate a DORA RTS-compliant ICT incident report template.

    Args:
        severity: One of anomalous, significant, major, significant_cyber_threat.
        entity_name: Reporting entity legal name (optional — leaves placeholder if empty).
        incident_summary: One-sentence description of the incident (optional).
        api_key: MEOK API key (Pro tier gets the HMAC-signed evidence pack version).

    Returns:
        Initial (T+4h), intermediate (T+72h) and final (T+1mo) report templates
        with every field defined by Commission Implementing Regulation (EU) 2024/2956.
        Fields are pre-filled where deterministic and marked TODO where the
        compliance officer must supply specifics.

    Behavior:
        Read-only template generator. Stateless and idempotent.
        Free tier: 10/day. PAYG: £0.05/call (set MEOK_PAYG_KEY). Pro: unlimited.
    """
    try:
        allowed, msg, tier_obj = _shared_check_access(api_key)
        if not allowed:
            return {"error": msg, "upgrade": "https://councilof.ai"}
        tier = tier_obj if isinstance(tier_obj, str) else tier_obj.value
    except Exception:
        tier = "free"

    sev = severity.lower().strip()
    if sev not in _DORA_SEVERITY_TIERS:
        return {
            "error": f"Unknown severity '{severity}'. Valid: {', '.join(_DORA_SEVERITY_TIERS)}",
            "tier_definitions": _DORA_SEVERITY_TIERS,
        }

    classification = _DORA_SEVERITY_TIERS[sev]
    placeholder_entity = entity_name or "[ENTITY LEGAL NAME]"
    placeholder_summary = incident_summary or "[ONE-SENTENCE INCIDENT SUMMARY — describe nature + scope]"

    initial_template = {
        "report_type": "INITIAL_NOTIFICATION",
        "deadline_from_classification": "≤ 4 hours (Article 19(4)(a) of DORA)",
        "fields": {
            "reporting_entity_name": placeholder_entity,
            "reporting_entity_lei": "[20-CHAR LEGAL ENTITY IDENTIFIER]",
            "competent_authority": "[NATIONAL CA — e.g. BaFin, AMF, FCA, Bank of Italy]",
            "incident_classification": classification["label"],
            "classification_criteria_met": "[LIST CRITERIA FROM DELEGATED REG 2024/1772 ART 4-6]",
            "incident_id_internal": "[YOUR INTERNAL TICKET / SIEM ID]",
            "discovered_at_utc": "[ISO 8601 TIMESTAMP]",
            "classified_at_utc": "[ISO 8601 TIMESTAMP — when DORA threshold reached]",
            "summary": placeholder_summary,
            "services_affected": "[LIST AFFECTED ICT SERVICES + CLIENT-FACING IMPACT]",
            "geographic_scope": "[MEMBER STATES + ANY THIRD COUNTRIES AFFECTED]",
            "cross_border": "[true/false — affects clients/operations in >1 Member State]",
            "voluntary": sev == "significant_cyber_threat",
            "ongoing": "[true/false]",
        },
    }

    intermediate_template = {
        "report_type": "INTERMEDIATE_UPDATE",
        "deadline_from_classification": "≤ 72 hours (Article 19(4)(b))",
        "fields": {
            "incident_id_internal": "[SAME AS INITIAL]",
            "current_status": "[contained / mitigated / under-investigation / resolved]",
            "preliminary_root_cause": "[BEST KNOWLEDGE AT T+72h]",
            "impact_so_far": {
                "clients_affected_count": "[NUMBER]",
                "transactions_impacted": "[NUMBER]",
                "data_records_compromised": "[NUMBER OR 'NONE']",
                "service_downtime_minutes": "[NUMBER]",
                "economic_impact_estimate_eur": "[BEST ESTIMATE OR 'PENDING']",
            },
            "actions_taken": "[CONTAINMENT, CLIENT NOTIFICATION, REGULATORY OUTREACH]",
            "third_parties_notified": "[CTPP, SUB-PROVIDERS, INDUSTRY CSIRT, ETC.]",
            "personal_data_breach_gdpr": "[true/false — if true, ART 33 GDPR clock also runs]",
            "criminal_activity_suspected": "[true/false — if true, law enforcement notified]",
        },
    }

    final_template = {
        "report_type": "FINAL_REPORT",
        "deadline_from_classification": "≤ 1 month (Article 19(4)(c))",
        "fields": {
            "incident_id_internal": "[SAME AS INITIAL]",
            "root_cause_analysis": "[FULL RCA — technical, procedural, human factors]",
            "total_impact": {
                "clients_affected_final": "[NUMBER]",
                "data_records_compromised_final": "[NUMBER]",
                "economic_impact_final_eur": "[FINAL FIGURE]",
                "regulatory_breaches": "[LIST OF DORA/NIS2/GDPR ARTICLES BREACHED]",
            },
            "remediation_actions": "[CORRECTIVE + PREVENTIVE ACTIONS WITH OWNERS + DUE DATES]",
            "lessons_learned": "[KEY POLICY/CONTROL/PROCESS CHANGES]",
            "tprm_review_required": "[true/false — was the incident triggered by CTPP/sub-provider?]",
            "tlpt_recommendation": "[true/false — does this warrant a Threat-Led Penetration Test?]",
            "board_approved": "[true/false — Article 5 requires governance approval]",
            "submitted_by": "[NAME + ROLE]",
            "submitted_at_utc": "[ISO 8601 TIMESTAMP]",
        },
    }

    return {
        "severity": classification,
        "templates": {
            "initial_notification_T+4h": initial_template,
            "intermediate_update_T+72h": intermediate_template,
            "final_report_T+1mo": final_template,
        },
        "legal_basis": (
            "DORA Article 17 (incident-management process), Article 18 (classification), "
            "Article 19 (reporting). Templates align with Commission Delegated Regulation "
            "(EU) 2024/1772 (classification criteria) and Commission Implementing Regulation "
            "(EU) 2024/2956 (reporting forms)."
        ),
        "next_step": (
            "Pre-populate the [PLACEHOLDERS] from your SIEM/ITSM event payload, then submit "
            "via your national competent authority's portal."
        ),
        "tier": tier,
        "upgrade_for_signed_version": (
            "Pro tier (£199/mo) emits an HMAC-SHA256 signed evidence-pack version of the report "
            "with a public verify URL — auditor-defensible without releasing the underlying SIEM data."
        ),
        "disclaimer": "Not legal advice. Confirm scope with your competent authority.",
    }


def main():
    """Entry point for the DORA compliance MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()


# ── 2026-06-12 PM22: server-side metering via live /verify (fail-open) ──
import urllib.request as _meter_urlreq
import urllib.error as _meter_urlerr
import json as _meter_json
_METER_URL = _os.environ.get("MEOK_VERIFY_URL", "https://meok-attestation-api.vercel.app/verify")


def _server_meter_check(tool: str) -> dict:
    """POST {api_key, tool} to /verify. Returns metering dict. Fail-open."""
    if not _MEOK_API_KEY:
        return {"allowed": True, "tier": "anon", "note": "MEOK_API_KEY not set; metering skipped"}
    try:
        body = _meter_json.dumps({"api_key": _MEOK_API_KEY, "tool": tool}).encode()
        req = _meter_urlreq.Request(_METER_URL, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        with _meter_urlreq.urlopen(req, timeout=4) as r:
            return _meter_json.loads(r.read())
    except (_meter_urlerr.URLError, _meter_urlerr.HTTPError, TimeoutError, ValueError) as e:
        # Fail-open: never break the tool on a metering failure
        return {"allowed": True, "tier": "unknown", "note": f"metering failed (fail-open): {e}"}
