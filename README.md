<div align="center">

# Dora Compliance MCP

**MCP server for dora compliance mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-dora-compliance-mcp)](https://pypi.org/project/meok-dora-compliance-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Dora Compliance MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `classify_entity` | Classify a financial entity's DORA applicability + which entity type it is. |
| `list_pillars` | List all 5 DORA pillars with article ranges and key obligations. |
| `audit_pillar` | Audit a specific DORA pillar (1-5) against your entity's current controls. |
| `audit_all_pillars` | Run audits across all 5 DORA pillars and return an executive summary. |
| `classify_incident` | Classify an ICT incident against DORA major-incident thresholds per Commission D |
| `register_of_information_template` | Return the Article 28.3 Register of Information template structure. Financial en |
| `tlpt_readiness` | Assess Threat-Led Penetration Testing (Article 26) readiness. Returns whether th |
| `get_dora_certificate` | Generate a cryptographically signed DORA compliance attestation (Pro/Enterprise) |
| `enforcement_status` | Current DORA enforcement status + key upcoming deadlines for financial entities. |

## Installation

```bash
pip install meok-dora-compliance-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "dora-compliance-mcp": {
      "command": "python",
      "args": ["-m", "meok_dora_compliance_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 9 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)

<!-- mcp-name: io.github.CSOAI-ORG/dora-compliance-mcp -->
