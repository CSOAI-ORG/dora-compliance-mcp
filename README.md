<!-- mcp-name: io.github.CSOAI-ORG/dora-compliance-mcp -->

> ### 🔏 Free tier: 50 calls/day. Need audit-ready proof?
> **Pro (£199/mo)** turns every result into an **HMAC-signed attestation** with a **public verify URL**
> your auditor validates without an account — EU AI Act Art 11/12 ready.
> → Start: **https://proofof.ai**  ·  `pip install meok-attestation-verify` to verify any cert.

[![MCP Scorecard: 90/100](https://img.shields.io/badge/proofof.ai-90%2F100-5b21b6)](https://proofof.ai/scorecard/dora-compliance-mcp.html)

# Dora Compliance MCP

[![MEOK AI Labs](https://img.shields.io/badge/MEOK-AI%20Labs-667eea)](https://meok.ai)
[![PAYG enabled](https://img.shields.io/badge/PAYG-%C2%A30.05%2Fcall-7c3aed?logo=stripe&logoColor=white&labelColor=1a1a2e)](https://councilof.ai/payg)
[![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Compliant-22c55e)](https://councilof.ai)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-Install-3775a9)](https://pypi.org/project/dora_compliance_mcp/)

> DORA (Regulation EU 2022/2554) compliance MCP for financial entities

DORA (Regulation EU 2022/2554) compliance MCP for financial entities. ICT risk, incident classification, reporting workflows. MIT

---

## 🚀 Quick Start

```bash
# Install via pip
pip install dora_compliance_mcp

# Or install via Smithery
npx -y @smithery/cli@latest install dora-compliance-mcp --client claude
```

## ⚡ Pay-per-call (PAYG) — no subscription

This MCP supports universal pay-per-call billing across the MEOK compliance fleet:

```bash
# One-time setup
export MEOK_PAYG_KEY="your_topup_token"

# Every tool call now deducts £0.05 from your balance.
# When balance hits zero, the tool returns a top-up URL.
# Works across all 7 MEOK compliance MCPs with the same token.
```

- **No subscription** — top up once, deduct per call.
- **£0.05/call default** (configurable via `MEOK_PAYG_RATE_GBP`).
- **USDC on Base L2 accepted** — set `MEOK_X402_RECEIVER` and pay via stablecoin.
- **Backward-compatible** — when `MEOK_PAYG_KEY` is unset, behaviour is unchanged.

**Get a token**: [councilof.ai/payg](https://councilof.ai/payg) (£10 / £50 / £200 top-up tiers).


## ✨ Features

- MCP protocol compliant
- Easy installation
- Well-documented API
- Production-ready
- Active maintenance

## 📖 Documentation

- [Full Documentation](https://docs.meok.ai/dora-compliance-mcp)
- [API Reference](https://meok-attestation-api.vercel.app)
- [EU AI Act Compliance Guide](https://councilof.ai)

## 🛡️ Compliance

This MCP server is built with **EU AI Act compliance** built-in:

- ✅ Article 9 — Risk Management System
- ✅ Article 13 — Transparency & Instructions for Use
- ✅ Article 15 — Bias Detection & Testing
- ✅ Article 26 — FRIA Support (where applicable)
- ✅ Article 50 — AI Content Watermarking (where applicable)

Need help getting compliant? **[Book a free 15-min diagnostic →](mailto:nicholas@meok.ai?subject=Compliance%20diagnostic)**

## 🏢 Enterprise

Need custom development, SLA guarantees, or white-label deployment?

- **Pro:** £79/mo — Full MCP suite + EU AI Act tracking
- **Enterprise:** £499/mo — Custom dev + SLA + Dedicated support

[View Pricing →](https://councilof.ai/payg) | [Contact Sales →](mailto:sales@meok.ai)

## 🤝 Part of the MEOK Ecosystem

This server is part of the **[MEOK AI Labs](https://meok.ai)** ecosystem — 26 PyPI packages · ~16,300 monthly installs.

| Domain | Purpose |
|--------|---------|
| [councilof.ai](https://councilof.ai) | EU AI Act compliance marketplace |
| [safetyof.ai](https://safetyof.ai) | AI safety & monitoring |
| [meok.ai](https://meok.ai) | Sovereign AI platform |
| [cobolbridge.ai](https://cobolbridge.ai) | Legacy modernization |

## 📜 License

MIT © [CSOAI-ORG](https://github.com/CSOAI-ORG)

---

<p align="center">
  <sub>Built with 💜 by <a href="https://meok.ai">MEOK AI Labs</a> · UK Companies House 16939677</sub>
</p>


## Configuration

Add to your `claude_desktop_config.json` (Claude Desktop) or your MCP client config:

```json
{
  "mcpServers": {
    "dora-compliance-mcp": {
      "command": "uvx",
      "args": ["dora-compliance-mcp"]
    }
  }
}
```

Or: `pip install dora-compliance-mcp` then run the `dora-compliance-mcp` command (stdio transport).

## Examples

Once configured, ask your assistant, for example:
- "Use `classify_entity` to …"
- "Use `list_pillars` to …"
- "Use `audit_pillar` to …"
