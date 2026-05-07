<div align="center">

[![PyPI](https://img.shields.io/pypi/v/dora-compliance-mcp)](https://pypi.org/project/dora-compliance-mcp/)
[![Downloads](https://img.shields.io/pypi/dm/dora-compliance-mcp)](https://pypi.org/project/dora-compliance-mcp/)
[![GitHub stars](https://img.shields.io/github/stars/CSOAI-ORG/dora-compliance-mcp)](https://github.com/CSOAI-ORG/dora-compliance-mcp/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

# DORA Compliance MCP

**Automate DORA (Digital Operational Resilience Act) compliance for EU financial entities.**

Regulation (EU) 2022/2554 — enforcement live since 17 January 2025. Penalties: up to 1% of average daily worldwide turnover for CTPPs.

[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-224+_servers-purple)](https://meok.ai)

[Install](#install) · [Tools](#tools) · [Pricing](#pricing) · [Attestation API](#attestation-api)

</div>

---

## Why This Exists

DORA has been enforceable since January 2025. Every EU bank, insurer, investment firm, and their critical ICT providers must demonstrate operational resilience across 5 pillars. The regulation requires ICT risk management frameworks, incident reporting within 4 hours, threat-led penetration testing (TLPT), and third-party risk registers.

Traditional DORA compliance involves hiring consultancies at €800-1,500/day for 6-12 months. This MCP automates the 5-pillar assessment, generates Article 28 register entries, runs TLPT planning checklists, and produces incident classification templates — all from a single Claude prompt.

## Install

```bash
pip install dora-compliance-mcp
```

## Tools

| Tool | DORA Pillar | What it does |
|------|-------------|-------------|
| `assess_ict_risk` | Pillar 1 | ICT risk management framework assessment |
| `classify_incident` | Pillar 2 | Incident classification per Article 18 criteria |
| `plan_tlpt` | Pillar 3 | Threat-led penetration testing planning |
| `assess_third_party` | Pillar 4 | Article 28 ICT third-party risk register |
| `check_information_sharing` | Pillar 5 | Information sharing arrangement audit |
| `run_full_audit` | All 5 | Complete 5-pillar DORA readiness assessment |
| `sign_attestation` | — | HMAC-SHA256 signed compliance certificate |

## Example

```
Prompt: "Our bank uses 3 cloud providers and 2 SaaS fintech tools.
Run a full DORA 5-pillar assessment. Flag any ICT concentration risk
and generate the Article 28 register entries."

Result: 5-pillar assessment with ICT concentration risk flagged on
cloud provider dependency, Article 28 register entries for all 5
third parties, incident reporting template, TLPT scope recommendation.
Each section signed with attestation cert.
```

## Pricing

| Tier | Price | What you get |
|------|-------|-------------|
| **Free** | £0 | 10 calls/day — risk assessment + incident classification |
| **Pro** | £199/mo | Unlimited + HMAC-signed attestations + verify URLs |
| **Enterprise** | £1,499/mo | Multi-tenant + co-branded reports + webhooks |

[Subscribe to Pro](https://buy.stripe.com/14A4gB3K4eUWgYR56o8k836) · [Enterprise](https://buy.stripe.com/4gM9AV80kaEG0ZT42k8k837)

## Attestation API

```
POST https://meok-attestation-api.vercel.app/sign
GET  https://meok-attestation-api.vercel.app/verify/{cert_id}
```

Zero-dep verifier: `pip install meok-attestation-verify`

## Links

- Website: [meok.ai](https://meok.ai)
- All MCP servers: [meok.ai/labs/mcp/servers](https://meok.ai/labs/mcp/servers)
- Also see: [DORA + NIS2 Crosswalk MCP](https://github.com/CSOAI-ORG/dora-nis2-crosswalk-mcp) for dual compliance
- Enterprise support: nicholas@csoai.org

## License

MIT
