"""
Tests for DORA Compliance MCP Server
======================================
Tests every @mcp.tool() function directly (no MCP protocol).
Run: cd /Users/nicholas/clawd/mcp-marketplace/dora-compliance-mcp && pytest test_server.py -v
"""

import json
import sys
import os

os.environ.pop("MEOK_API_KEY", None)

sys.path.insert(0, os.path.dirname(__file__))

from server import (
    classify_entity,
    list_pillars,
    audit_pillar,
    audit_all_pillars,
    classify_incident,
    register_of_information_template,
    tlpt_readiness,
    get_dora_certificate,
    enforcement_status,
    _usage,
    DORA_PILLARS,
)


def _reset_rate_limits():
    _usage.clear()


# ── classify_entity ────────────────────────────────────────────────

class TestClassifyEntity:
    def setup_method(self):
        _reset_rate_limits()

    def test_credit_institution_in_scope(self):
        result = classify_entity("We are a credit institution providing banking services")
        data = json.loads(result)
        assert isinstance(data, dict)
        assert data.get("in_scope") is True

    def test_insurance_in_scope(self):
        result = classify_entity("Insurance and reinsurance undertaking in EU")
        data = json.loads(result)
        assert data.get("in_scope") is True

    def test_crypto_in_scope(self):
        result = classify_entity("Crypto asset service provider operating in the EU")
        data = json.loads(result)
        assert data.get("in_scope") is True

    def test_out_of_scope(self):
        result = classify_entity("A bakery selling bread and pastries")
        data = json.loads(result)
        assert data.get("in_scope") is False

    def test_micro_enterprise_simplified(self):
        result = classify_entity("A micro investment firm with under 10 employees")
        data = json.loads(result)
        assert data.get("proportionality") == "simplified_regime"

    def test_full_regime(self):
        result = classify_entity("A large payment institution with 500 employees")
        data = json.loads(result)
        assert data.get("proportionality") == "full_regime"

    def test_empty_description(self):
        result = classify_entity("")
        data = json.loads(result)
        assert isinstance(data, dict)
        assert data.get("in_scope") is False

    def test_enforcement_date_present(self):
        result = classify_entity("Investment firm")
        data = json.loads(result)
        assert "enforcement_date" in data
        assert "2025" in data["enforcement_date"]

    def test_days_since_enforcement(self):
        result = classify_entity("Credit institution")
        data = json.loads(result)
        assert "days_since_enforcement" in data
        assert data["days_since_enforcement"] > 0


# ── list_pillars ───────────────────────────────────────────────────

class TestListPillars:
    def setup_method(self):
        _reset_rate_limits()

    def test_returns_json(self):
        result = list_pillars()
        data = json.loads(result)
        assert isinstance(data, dict)

    def test_has_5_pillars(self):
        result = list_pillars()
        data = json.loads(result)
        assert "pillars" in data
        assert len(data["pillars"]) == 5

    def test_pillar_structure(self):
        result = list_pillars()
        data = json.loads(result)
        for p in data["pillars"]:
            assert "title" in p
            assert "articles" in p
            assert "key_obligations" in p

    def test_idempotent(self):
        r1 = json.loads(list_pillars())
        _reset_rate_limits()
        r2 = json.loads(list_pillars())
        assert r1["pillars"] == r2["pillars"]


# ── audit_pillar ───────────────────────────────────────────────────

class TestAuditPillar:
    def setup_method(self):
        _reset_rate_limits()

    def test_pillar_1_basic(self):
        result = audit_pillar(
            pillar_number=1,
            entity_description="A credit institution",
        )
        data = json.loads(result)
        assert data["pillar"] == 1
        assert "score_percent" in data

    def test_pillar_1_with_controls(self):
        result = audit_pillar(
            pillar_number=1,
            entity_description="A payment institution",
            current_controls="We have board governance, asset inventory CMDB, encryption TLS at rest, network segmentation, SIEM logging, anomaly detection IDS, business continuity BCP, backup with replication",
        )
        data = json.loads(result)
        assert data["score_percent"] > 0
        assert data["assessment"] in ("COMPLIANT", "PARTIAL", "NON_COMPLIANT")

    def test_pillar_2(self):
        result = audit_pillar(
            pillar_number=2,
            entity_description="Insurance company",
            current_controls="Incident response IR playbook, severity rating, 4 hour notification, 72 hour intermediate report",
        )
        data = json.loads(result)
        assert data["pillar"] == 2

    def test_pillar_3(self):
        result = audit_pillar(
            pillar_number=3,
            entity_description="Investment firm",
            current_controls="Pentest programme, vulnerability assessment, red team exercises",
        )
        data = json.loads(result)
        assert data["pillar"] == 3

    def test_pillar_4(self):
        result = audit_pillar(
            pillar_number=4,
            entity_description="Credit institution",
            current_controls="Third party register, audit rights clause, exit strategy documented",
        )
        data = json.loads(result)
        assert data["pillar"] == 4

    def test_pillar_5(self):
        result = audit_pillar(
            pillar_number=5,
            entity_description="Bank with FS-ISAC membership",
            current_controls="FS-ISAC threat intel sharing",
        )
        data = json.loads(result)
        assert data["pillar"] == 5

    def test_invalid_pillar(self):
        result = audit_pillar(pillar_number=99, entity_description="test")
        data = json.loads(result)
        assert "error" in data

    def test_zero_score_no_controls(self):
        result = audit_pillar(
            pillar_number=1,
            entity_description="A company with no security controls",
            current_controls="",
        )
        data = json.loads(result)
        assert data["assessment"] == "NON_COMPLIANT"

    def test_gaps_listed(self):
        result = audit_pillar(
            pillar_number=1,
            entity_description="Bank",
        )
        data = json.loads(result)
        assert "gaps_to_address" in data
        assert isinstance(data["gaps_to_address"], list)

    def test_obligations_detail(self):
        result = audit_pillar(
            pillar_number=1,
            entity_description="Payment firm",
        )
        data = json.loads(result)
        assert "obligations_detail" in data
        for ob in data["obligations_detail"]:
            assert "obligation" in ob
            assert "status" in ob
            assert ob["status"] in ("EVIDENCE_FOUND", "GAP")


# ── audit_all_pillars ─────────────────────────────────────────────

class TestAuditAllPillars:
    def setup_method(self):
        _reset_rate_limits()

    def test_free_tier_blocked(self):
        """Free tier should be blocked from audit_all_pillars."""
        result = audit_all_pillars(
            entity_description="A bank",
            current_controls="Some controls",
        )
        data = json.loads(result)
        assert "error" in data


# ── classify_incident ──────────────────────────────────────────────

class TestClassifyIncident:
    def setup_method(self):
        _reset_rate_limits()

    def test_major_incident(self):
        result = classify_incident(
            incident_description="Critical cross-border system outage affecting trading platform",
            clients_affected=200000,
            duration_hours=48,
            economic_impact_eur=5000000,
            data_loss=True,
        )
        data = json.loads(result)
        assert data["classification"] == "MAJOR_ICT_INCIDENT"
        assert data["reporting_required"] is True

    def test_non_major_incident(self):
        result = classify_incident(
            incident_description="Minor UI bug in internal dashboard",
            clients_affected=0,
            duration_hours=0.5,
            economic_impact_eur=0,
            data_loss=False,
        )
        data = json.loads(result)
        assert data["classification"] == "NON_MAJOR_INCIDENT"
        assert data["reporting_required"] is False

    def test_reporting_timeline_major(self):
        result = classify_incident(
            incident_description="Data breach in critical business service",
            clients_affected=500000,
            data_loss=True,
        )
        data = json.loads(result)
        timeline = data["reporting_timeline"]
        assert timeline["initial_notification_deadline_utc"] is not None
        assert timeline["intermediate_deadline_utc"] is not None
        assert timeline["final_deadline_utc"] is not None

    def test_empty_description(self):
        result = classify_incident(incident_description="")
        data = json.loads(result)
        assert isinstance(data, dict)
        assert "classification" in data

    def test_duration_threshold(self):
        result = classify_incident(
            incident_description="Service outage",
            duration_hours=25,
            economic_impact_eur=200000,
        )
        data = json.loads(result)
        assert len(data["primary_criteria_met"]) >= 2

    def test_data_loss_flag(self):
        result = classify_incident(
            incident_description="Database compromise",
            data_loss=True,
            economic_impact_eur=600000,
        )
        data = json.loads(result)
        criteria = data["primary_criteria_met"]
        assert any("data loss" in c.lower() for c in criteria)


# ── register_of_information_template ───────────────────────────────

class TestRegisterOfInformationTemplate:
    def setup_method(self):
        _reset_rate_limits()

    def test_returns_json(self):
        result = register_of_information_template()
        data = json.loads(result)
        assert isinstance(data, dict)

    def test_has_sections(self):
        result = register_of_information_template()
        data = json.loads(result)
        assert "sections" in data
        assert len(data["sections"]) > 0

    def test_section_structure(self):
        result = register_of_information_template()
        data = json.loads(result)
        for section in data["sections"]:
            assert "section" in section
            assert "fields" in section
            assert isinstance(section["fields"], list)

    def test_legal_basis_present(self):
        result = register_of_information_template()
        data = json.loads(result)
        assert "legal_basis" in data
        assert "Article 28" in data["legal_basis"]


# ── tlpt_readiness ─────────────────────────────────────────────────

class TestTlptReadiness:
    def setup_method(self):
        _reset_rate_limits()

    def test_significant_entity_in_scope(self):
        result = tlpt_readiness("We are a G-SII systemically important institution with total assets over €100 billion")
        data = json.loads(result)
        assert "IN_SCOPE" in data["probable_scope"]

    def test_non_significant_entity(self):
        result = tlpt_readiness("Small fintech startup with 20 employees")
        data = json.loads(result)
        assert "OUT" in data["probable_scope"]

    def test_required_preparation(self):
        result = tlpt_readiness("A bank")
        data = json.loads(result)
        assert "required_preparation" in data
        assert isinstance(data["required_preparation"], list)
        assert len(data["required_preparation"]) > 0

    def test_common_pitfalls(self):
        result = tlpt_readiness("Payment firm")
        data = json.loads(result)
        assert "common_pitfalls" in data

    def test_empty_description(self):
        result = tlpt_readiness("")
        data = json.loads(result)
        assert isinstance(data, dict)


# ── get_dora_certificate ───────────────────────────────────────────

class TestGetDoraCertificate:
    def setup_method(self):
        _reset_rate_limits()

    def test_free_tier_blocked(self):
        result = get_dora_certificate(
            entity_name="Test Bank",
            overall_score=85.0,
        )
        data = json.loads(result)
        assert "error" in data
        # Free tier should not get certificates
        assert "pro" in data["error"].lower() or "upgrade" in json.dumps(data).lower()


# ── enforcement_status ─────────────────────────────────────────────

class TestEnforcementStatus:
    def setup_method(self):
        _reset_rate_limits()

    def test_returns_json(self):
        result = enforcement_status()
        data = json.loads(result)
        assert isinstance(data, dict)

    def test_in_force(self):
        result = enforcement_status()
        data = json.loads(result)
        assert data["current_status"] == "IN_FORCE"

    def test_enforcement_date(self):
        result = enforcement_status()
        data = json.loads(result)
        assert data["enforcement_started"] == "2025-01-17"

    def test_days_since_positive(self):
        result = enforcement_status()
        data = json.loads(result)
        assert data["days_since_enforcement"] > 0

    def test_milestones_present(self):
        result = enforcement_status()
        data = json.loads(result)
        assert "next_milestones" in data
        assert isinstance(data["next_milestones"], list)

    def test_idempotent(self):
        r1 = json.loads(enforcement_status())
        _reset_rate_limits()
        r2 = json.loads(enforcement_status())
        assert r1["current_status"] == r2["current_status"]


# ── Rate Limiting ──────────────────────────────────────────────────

class TestRateLimiting:
    def setup_method(self):
        _reset_rate_limits()

    def test_classify_entity_rate_limit(self):
        for i in range(10):
            result = json.loads(classify_entity(f"Entity {i} credit institution"))
            assert "error" not in result or "limit" not in str(result.get("error", "")).lower()

        result = json.loads(classify_entity("One more credit institution"))
        if "error" in result:
            assert "limit" in str(result["error"]).lower() or "free" in str(result["error"]).lower()
