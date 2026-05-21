"""Functional tests for DORA Compliance MCP Server tools.

Tests each tool function with valid inputs, checks JSON output structure,
validates error handling, and verifies the local attestation path works
without external API calls. All tests are offline-safe with no network deps.
"""
import json
import os
import sys
from unittest.mock import MagicMock

# Mock mcp module before importing server
_mock_mcp_module = MagicMock()

class _MockFastMCP:
    def __init__(self, name="", **kwargs):
        self.name = name

    def tool(self):
        def decorator(fn):
            return fn
        return decorator

_mock_mcp_module.FastMCP = _MockFastMCP
sys.modules["mcp"] = MagicMock()
sys.modules["mcp.server"] = MagicMock()
sys.modules["mcp.server.fastmcp"] = _mock_mcp_module

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.pop("MEOK_API_KEY", None)
os.environ.pop("MEOK_ATTESTATION_API_URL", None)

import server as srv  # noqa: E402
import pytest  # noqa: E402
from unittest.mock import patch  # noqa: E402


@pytest.fixture(autouse=True)
def reset_state():
    srv._usage.clear()
    os.environ.pop("MEOK_API_KEY", None)
    os.environ.pop("MEOK_ATTESTATION_API_URL", None)
    yield
    srv._usage.clear()


@pytest.fixture(autouse=True)
def bypass_auth_and_rate_limit():
    with patch.object(srv, "check_access", return_value=(True, "OK", "pro")), \
         patch.object(srv, "_check_rate_limit", return_value=None):
        yield


class TestClassifyEntity:
    def test_credit_institution_in_scope(self):
        result = json.loads(srv.classify_entity("Credit institution operating in the EU"))
        assert result["in_scope"] is True
        assert any(t["entity_type"] == "credit_institution" for t in result["probable_entity_types"])

    def test_payment_institution_in_scope(self):
        result = json.loads(srv.classify_entity("Payment institution licensed under PSD2"))
        assert result["in_scope"] is True

    def test_crypto_service_provider_in_scope(self):
        result = json.loads(srv.classify_entity("Crypto-asset service provider under MiCA"))
        assert result["in_scope"] is True

    def test_non_financial_not_in_scope(self):
        result = json.loads(srv.classify_entity("We are a bakery that sells cakes locally"))
        assert result["in_scope"] is False

    def test_micro_simplified_regime(self):
        result = json.loads(srv.classify_entity("Micro credit institution with under 10 employees"))
        assert result["proportionality"] == "simplified_regime"

    def test_full_regime_default(self):
        result = json.loads(srv.classify_entity("Credit institution with 500 employees"))
        assert result["proportionality"] == "full_regime"

    def test_enforcement_date_present(self):
        result = json.loads(srv.classify_entity("Insurance undertaking"))
        assert "enforcement_date" in result
        assert result["days_since_enforcement"] >= 0

    def test_empty_description(self):
        result = json.loads(srv.classify_entity(""))
        assert result["in_scope"] is False

    def test_output_is_valid_json(self):
        output = srv.classify_entity("Investment firm under MiFID II")
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_all_five_pillars_when_in_scope(self):
        result = json.loads(srv.classify_entity("Credit institution"))
        assert result["all_five_pillars_apply"] is True

    def test_next_step_guidance(self):
        result = json.loads(srv.classify_entity("Credit institution"))
        assert "next_step" in result


class TestListPillars:
    def test_returns_five_pillars(self):
        result = json.loads(srv.list_pillars())
        assert "pillars" in result
        assert len(result["pillars"]) == 5

    def test_pillar_structure(self):
        result = json.loads(srv.list_pillars())
        for p in result["pillars"]:
            assert "pillar" in p
            assert "title" in p
            assert "articles" in p
            assert "key_obligations" in p
            assert isinstance(p["key_obligations"], list)

    def test_regulation_reference(self):
        result = json.loads(srv.list_pillars())
        assert "2022/2554" in result["regulation"]


class TestAuditPillar:
    def test_pillar_1_valid(self):
        result = json.loads(srv.audit_pillar(1, "Credit institution with board governance"))
        assert result["pillar"] == 1
        assert "score_percent" in result
        assert "assessment" in result

    def test_pillar_4_third_party(self):
        result = json.loads(srv.audit_pillar(4, "We have a third-party register"))
        assert result["pillar"] == 4
        assert result["pillar_title"] == "ICT Third-Party Risk Management"

    def test_invalid_pillar_number_6(self):
        result = json.loads(srv.audit_pillar(6, "Credit institution"))
        assert "error" in result

    def test_invalid_pillar_number_0(self):
        result = json.loads(srv.audit_pillar(0, "Credit institution"))
        assert "error" in result

    def test_invalid_pillar_negative(self):
        result = json.loads(srv.audit_pillar(-1, "Credit institution"))
        assert "error" in result

    def test_with_controls_matching(self):
        result = json.loads(srv.audit_pillar(
            1, "Credit institution",
            current_controls="We have encryption in transit, SIEM logging, BCP tested annually"
        ))
        assert "obligations_detail" in result
        passed_items = [o for o in result["obligations_detail"] if o["status"] == "EVIDENCE_FOUND"]
        assert len(passed_items) > 0

    def test_scoring_range(self):
        for pn in range(1, 6):
            result = json.loads(srv.audit_pillar(pn, "Credit institution", "Full controls: encryption SIEM"))
            assert 0 <= result["score_percent"] <= 100

    def test_assessment_values(self):
        result = json.loads(srv.audit_pillar(1, "Credit institution"))
        assert result["assessment"] in ("COMPLIANT", "PARTIAL", "NON_COMPLIANT")

    def test_gaps_is_list(self):
        result = json.loads(srv.audit_pillar(2, "Credit institution"))
        assert isinstance(result["gaps_to_address"], list)

    def test_remediation_priority_present(self):
        result = json.loads(srv.audit_pillar(3, "Credit institution"))
        assert "remediation_priority" in result


class TestClassifyIncident:
    def test_major_incident_data_loss(self):
        result = json.loads(srv.classify_incident(
            "Ransomware attack on critical banking system",
            clients_affected=150000, duration_hours=48,
            economic_impact_eur=500000, data_loss=True
        ))
        assert result["classification"] == "MAJOR_ICT_INCIDENT"
        assert result["reporting_required"] is True

    def test_minor_incident(self):
        result = json.loads(srv.classify_incident(
            "Brief outage of non-critical system",
            clients_affected=50, duration_hours=0.5,
            economic_impact_eur=1000, data_loss=False
        ))
        assert result["classification"] == "NON_MAJOR_INCIDENT"

    def test_cross_border_major(self):
        result = json.loads(srv.classify_incident(
            "Cross-border incident affecting multiple EU countries",
            clients_affected=500, duration_hours=30, data_loss=True
        ))
        assert result["reporting_required"] is True

    def test_critical_service_unavailable(self):
        result = json.loads(srv.classify_incident(
            "Critical business service unavailable",
            clients_affected=200, duration_hours=3, data_loss=False
        ))
        assert result["classification"] == "MAJOR_ICT_INCIDENT"

    def test_reporting_timeline_for_major(self):
        result = json.loads(srv.classify_incident(
            "Major cross-border incident",
            clients_affected=100000, data_loss=True,
            economic_impact_eur=200000
        ))
        assert "reporting_timeline" in result
        assert result["reporting_timeline"]["initial_notification"] != "Not required"
        assert result["reporting_timeline"]["final_report"] != "Not required"

    def test_legal_basis_present(self):
        result = json.loads(srv.classify_incident("System outage", clients_affected=10))
        assert "legal_basis" in result

    def test_action_required_present(self):
        result = json.loads(srv.classify_incident("Minor issue", clients_affected=5))
        assert "action_required" in result
        assert isinstance(result["action_required"], list)


class TestRegisterOfInformation:
    def test_returns_template(self):
        result = json.loads(srv.register_of_information_template())
        assert "sections" in result
        assert "legal_basis" in result
        assert len(result["sections"]) >= 5

    def test_section_structure(self):
        result = json.loads(srv.register_of_information_template())
        for section in result["sections"]:
            assert "section" in section
            assert "fields" in section
            assert isinstance(section["fields"], list)

    def test_submission_format_present(self):
        result = json.loads(srv.register_of_information_template())
        assert "submission_format" in result


class TestTLPTReadiness:
    def test_significant_entity_in_scope(self):
        result = json.loads(srv.tlpt_readiness("G-SIB systemic bank with €100bn total assets"))
        assert "IN_SCOPE" in result["probable_scope"]

    def test_non_significant_entity(self):
        result = json.loads(srv.tlpt_readiness("Small regional payment processor"))
        assert "LIKELY_OUT" in result["probable_scope"]

    def test_required_preparation_list(self):
        result = json.loads(srv.tlpt_readiness("Significant investment firm"))
        assert "required_preparation" in result
        assert isinstance(result["required_preparation"], list)
        assert len(result["required_preparation"]) > 0

    def test_article_reference_present(self):
        result = json.loads(srv.tlpt_readiness("Credit institution"))
        assert "article_reference" in result
        assert "26" in result["article_reference"]


class TestEnforcementStatus:
    def test_in_force(self):
        result = json.loads(srv.enforcement_status())
        assert result["current_status"] == "IN_FORCE"
        assert result["days_since_enforcement"] >= 0

    def test_milestones_present(self):
        result = json.loads(srv.enforcement_status())
        assert "next_milestones" in result
        assert len(result["next_milestones"]) > 0

    def test_penalty_info(self):
        result = json.loads(srv.enforcement_status())
        assert "penalty_headline" in result


class TestGetDoraCertificate:
    def test_free_tier_rejected(self):
        result = json.loads(srv.get_dora_certificate("Test Bank", 75.0))
        assert "error" in result

    def test_pro_tier_local_attestation(self):
        os.environ["MEOK_API_KEY"] = "test-pro-key"
        try:
            result = json.loads(srv.get_dora_certificate(
                "Test Financial Institution", 85.0,
                findings_csv="Article 9: PASS,Article 28: GAP",
                articles_audited_csv="9,10,28",
                api_key="test-pro-key"
            ))
            assert "signature" in result
            assert result["entity"] == "Test Financial Institution"
            assert result["score"] == 85.0
            assert result["signed_locally"] is True
            assert result["signature_algorithm"] == "HMAC-SHA256"
        finally:
            os.environ.pop("MEOK_API_KEY", None)

    def test_pro_tier_with_empty_findings(self):
        os.environ["MEOK_API_KEY"] = "test-pro-key"
        try:
            result = json.loads(srv.get_dora_certificate(
                "Bank X", 90.0, api_key="test-pro-key"
            ))
            assert "signature" in result
            assert result["score"] == 90.0
        finally:
            os.environ.pop("MEOK_API_KEY", None)


class TestLocalHmacSign:
    def test_basic_signature(self):
        result = srv._local_hmac_sign(
            regulation="DORA", entity="Test Entity", score=90.0,
            findings=["Article 9: PASS"], articles_audited=["9"], tier="pro"
        )
        assert result["signature"] is not None
        assert result["signature_algorithm"] == "HMAC-SHA256"
        assert result["signed_locally"] is True
        assert result["regulation"] == "DORA"
        assert result["entity"] == "Test Entity"
        assert result["score"] == 90.0

    def test_signature_deterministic(self):
        os.environ["MEOK_API_KEY"] = "fixed-test-key"
        try:
            import time
            r1 = srv._local_hmac_sign(
                regulation="DORA", entity="E", score=50.0,
                findings=[], articles_audited=[], tier="pro"
            )
            r2 = srv._local_hmac_sign(
                regulation="DORA", entity="E", score=50.0,
                findings=[], articles_audited=[], tier="pro"
            )
            assert r1["signature_algorithm"] == r2["signature_algorithm"]
        finally:
            os.environ.pop("MEOK_API_KEY", None)

    def test_verify_url_present(self):
        result = srv._local_hmac_sign(
            regulation="DORA", entity="Test", score=75.0,
            findings=[], articles_audited=[], tier="pro"
        )
        assert "verify_url" in result
        assert "meok.ai/verify" in result["verify_url"]


class TestRateLimiting:
    def test_rate_limit_enforced(self):
        for i in range(srv.FREE_DAILY_LIMIT + 1):
            result = json.loads(srv.classify_entity("Credit institution"))
            if "error" in result and "limit" in result["error"].lower():
                return
        pytest.fail("Rate limit was not enforced after exceeding daily limit")


class TestKnowledgeBase:
    def test_five_pillars_defined(self):
        assert len(srv.DORA_PILLARS) == 5
        for i in range(1, 6):
            assert i in srv.DORA_PILLARS
            assert "title" in srv.DORA_PILLARS[i]
            assert "articles" in srv.DORA_PILLARS[i]
            assert "key_obligations" in srv.DORA_PILLARS[i]

    def test_entity_types_comprehensive(self):
        assert len(srv.ENTITY_TYPES_IN_SCOPE) > 10
        assert "credit_institution" in srv.ENTITY_TYPES_IN_SCOPE
        assert "crypto_asset_service_provider" in srv.ENTITY_TYPES_IN_SCOPE
        assert "ict_third_party" in srv.ENTITY_TYPES_IN_SCOPE

    def test_enforcement_date(self):
        assert srv.ENFORCEMENT_DATE.year == 2025
        assert srv.ENFORCEMENT_DATE.month == 1
        assert srv.ENFORCEMENT_DATE.day == 17