# DORA Compliance MCP

**The only MCP server that automates DORA (Digital Operational Resilience Act) compliance for EU financial entities.** Regulation (EU) 2022/2554 — enforcement live since 17 January 2025.

Built by [MEOK AI Labs](https://meok.ai). Pairs with our EU AI Act, GDPR, ISO 42001, and NIST AI RMF MCPs for full-stack regulatory coverage.

## What it does

Give any Claude / ChatGPT / Cursor / Cline agent the ability to:

- **Classify any financial entity's DORA applicability** (20+ entity types in scope)
- **Audit all 5 DORA pillars** — ICT risk management, incident management, resilience testing, third-party risk, information sharing
- **Classify ICT incidents** against Commission Delegated Regulation (EU) 2024/1772 thresholds (4h / 72h / 1-month reporting)
- **Generate Article 28 Register of Information** template — mandatory annual submission
- **Assess TLPT readiness** (Threat-Led Penetration Testing under Article 26, TIBER-EU aligned)
- **Track enforcement deadlines** and emit signed compliance certificates

## Install

```bash
pip install dora-compliance-mcp
```

## Use with Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dora": {
      "command": "dora-compliance-mcp"
    }
  }
}
```

Then ask Claude things like:

- *"Am I in scope for DORA? I run a UK-registered crypto exchange with EU customers."*
- *"Audit pillar 4 (ICT third-party risk) against this contract with AWS."*
- *"Classify this incident: 200,000 customers couldn't log in for 6 hours, we believe personal data was exposed."*
- *"Generate my Article 28 Register of Information template."*

## Tiers

- **Free** — 10 calls/day, pillar-by-pillar audits, incident classification
- **Pro (£49/mo)** — unlimited calls, full 5-pillar sweep, signed certificates, Register of Information generator
- **Enterprise (£499/mo)** — neural-net-backed gap detection, TLPT readiness, multi-entity audit, audit trail export
- **48-hour written assessment** (£5,000) — a senior compliance engineer delivers a full DORA gap report

Upgrade at [meok.ai/pricing](https://meok.ai/pricing).

## Why it matters

- Enforcement **LIVE since 17 January 2025** — first full reporting cycle running now
- **~22,000 EU financial entities in scope** (banks, insurance, fintech, crypto, investment firms, ICT providers to banks)
- **Penalties up to 1% of daily global turnover** for Critical ICT Third-Party Providers (CTPPs)
- First annual Register of Information submissions due **30 April 2026**

If you supply ICT services to EU banks, you're now directly in scope via the CTPP designation process — even if you're not a financial entity yourself.

## Legal basis

- Regulation (EU) 2022/2554 (DORA)
- Commission Delegated Regulation (EU) 2024/1772 — incident classification
- Commission Implementing Regulation (EU) 2024/2956 — Register of Information template
- ESAs Regulatory Technical Standards on TLPT (Article 26)

This is automated self-assessment tooling. It does not substitute for competent-authority review or legal counsel.

## License

MIT. MEOK AI Labs, 2026.
