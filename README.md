<div align="center">

# DORA Compliance MCP

**EU Digital Operational Resilience Act (DORA) Compliance — 5-Pillar Audit, Incident Classification, TLPT**

[![MCP](https://img.shields.io/badge/MCP-Server-blue)](https://github.com/CSOAI-ORG)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
</div>

## Overview

Full compliance automation for the EU Digital Operational Resilience Act (Regulation 2022/2554). Covers all 5 pillars: ICT Risk Management, Incident Reporting, Digital Operational Resilience Testing, ICT Third-Party Risk, and Information Sharing.

## Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `audit_dora` | Full 5-pillar DORA compliance audit | `pillar`, `controls`, `entity_type` |
| `classify_ict_incident` | Classify ICT incidents per Article 19 criteria | `incident_type`, `impact`, `severity` |
| `assess_third_party_risk` | Assess ICT third-party risk per Articles 28-30 | `provider_name`, `service_criticality`, `contract_type` |
| `generate_register_of_info` | Generate Article 28 Register of Information entry | `third_party_name`, `service_category`, `contract_ref` |
| `tlpt_readiness` | Assess TLPT (Threat-Led Penetration Testing) readiness | `entity_type`, `current_testing`, `scope` |
| `digital_resilience_score` | Calculate overall digital resilience score | `findings`, `pillar_scores` |
| `incident_reporting_timeline` | Get incident reporting deadlines by severity | `severity`, `entity_type` |
| `contract_clause_checker` | Check third-party contracts for DORA compliance | `contract_clauses` |
| `gap_analysis` | Full DORA gap analysis with remediation plan | `current_state`, `entity_type` |

## Installation

```bash
pip install mcp
```

### Claude Desktop
```json
{
  "mcpServers": {
    "dora-compliance": {
      "command": "python",
      "args": ["path/to/server.py"]
    }
  }
}
```

### Cursor / VS Code / Windsurf
```json
{
  "mcpServers": {
    "dora-compliance": {
      "command": "python",
      "args": ["path/to/server.py"]
    }
  }
}
```

## Usage Examples

<<<<<<< Updated upstream
MIT © [MEOK AI Labs](https://meok.ai)


## Sister MCPs

Part of the MEOK **Governance** pack — designed to work together as a fleet. Install the whole pack with `npx meok-setup --pack governance`, or pick the ones you need:

- **EU AI Act** → `uvx eu-ai-act-compliance-mcp` · [PyPI](https://pypi.org/project/eu-ai-act-compliance-mcp/) · [GitHub](https://github.com/CSOAI-ORG/eu-ai-act-compliance-mcp)
- **NIS2** → `uvx nis2-compliance-mcp` · [PyPI](https://pypi.org/project/nis2-compliance-mcp/) · [GitHub](https://github.com/CSOAI-ORG/nis2-compliance-mcp)
- **Cyber Resilience Act** → `uvx cra-compliance-mcp` · [PyPI](https://pypi.org/project/cra-compliance-mcp/) · [GitHub](https://github.com/CSOAI-ORG/cra-compliance-mcp)
- **AI Bill of Materials** → `uvx ai-bom-mcp` · [PyPI](https://pypi.org/project/ai-bom-mcp/) · [GitHub](https://github.com/CSOAI-ORG/ai-bom-mcp)
- **AI Incident Reporting** → `uvx ai-incident-reporting-mcp` · [PyPI](https://pypi.org/project/ai-incident-reporting-mcp/) · [GitHub](https://github.com/CSOAI-ORG/ai-incident-reporting-mcp)
- **DORA × NIS2 Crosswalk** → `uvx dora-nis2-crosswalk-mcp` · [PyPI](https://pypi.org/project/dora-nis2-crosswalk-mcp/) · [GitHub](https://github.com/CSOAI-ORG/dora-nis2-crosswalk-mcp)

Full catalogue + Anthropic Registry verify links: [meok.ai/anthropic-registry](https://meok.ai/anthropic-registry)


## Protocol coverage + Universal PAYG

This MCP is part of MEOK's 47-MCP fleet that bridges every active agent-interop protocol
and 30+ regulatory frameworks. See the full coverage matrix at [meok.ai/protocols](https://meok.ai/protocols).

**Agent interop protocols supported (8 live):**

- ✅ **MCP** (Anthropic) — native
- ✅ **A2A** (Google + Linux Foundation, absorbed IBM ACP Sept 2025)
- ✅ **IBM ACP** — covered via A2A merge
- ◐ **Stripe ACP** (Agentic Commerce Protocol) — Q3 bridge via [agent-commerce-protocol-mcp](https://github.com/CSOAI-ORG/agent-commerce-protocol-mcp)
- ◐ **AP2** (Google Agent Payments) — partial via [agent-commerce-payments-mcp](https://github.com/CSOAI-ORG/agent-commerce-payments-mcp)
- ◐ **x402** (Coinbase HTTP 402) — partial via api.meok.ai gateway
- → **OASF / AGNTCY** (Cisco Outshift + Linux Foundation) — Q3 bridge
- 👁 **ANP** (Cisco Agent Network) — watch-list

**Pricing options:**

| Option | Price | Best for |
|---|---|---|
| Self-host (this MCP) | £0 — MIT | Devs |
| This MCP Starter | £29/mo | One-MCP teams |
| This MCP Pro | £79/mo | Production + 24h SLA |
| [Universal PAYG](https://buy.stripe.com/00w3cxcgAaEGcIBcyQ8k90s) | £29/mo + £0.0002/call | Spiky usage across many MCPs |
| Substrate bundle (this category) | £99-£499/mo | A whole pack |
| [MEOK Universe](https://buy.stripe.com/cNi9AV0xS8wy5g9aqI8k90u) | £1,499/mo | All 47 MCPs, 500K calls |

Each tier above the free self-host adds HMAC-signed attestations verifiable at
`verify.meok.ai`. Linux Foundation governance on the A2A spine means EU regulated
buyers can deploy without vendor-lock-in objections.

<!-- mcp-name: io.github.CSOAI-ORG/dora-compliance-mcp -->
=======
### Run a full DORA audit
```json
{
  "pillar": "ict_risk_management",
  "controls": ["incident response plan exists", "backups configured", "no formal testing"],
  "entity_type": "financial"
}
```

### Assess third-party risk
```json
{
  "provider_name": "AWS",
  "service_criticality": "critical",
  "contract_type": "cloud_infrastructure"
}
```

## Pricing

- **Free:** 10 audits/day
- **Pro:** $99/mo — unlimited audits + reports
- **Enterprise:** $499/mo — full TLPT + third-party register

---

*Built by MEOK AI Labs | [meok.ai](https://meok.ai)*
>>>>>>> Stashed changes

## Wire it up — full stack

Pair this with the MEOK chain that turns one agent action into ONE signed compliance event:

1. **bft-progress-council-mcp** — anti-loop guardrail
2. **agent-token-budget-mcp** — hard spend cap
3. **agent-prompt-injection-firewall-mcp** — OWASP LLM01 scan
4. **agent-audit-logger-mcp** — hash-chained evidence
5. **a2a-governance-bridge-mcp** — fold N attestations → 1 signed event
6. **agent-incident-relay-mcp** — broadcast incidents to 5 regimes simultaneously

See [meok.ai/mcp-stack](https://meok.ai/mcp-stack) for the full architecture and [meok.ai/mcp-stack/demo](https://meok.ai/mcp-stack/demo) for the live in-browser demo.
