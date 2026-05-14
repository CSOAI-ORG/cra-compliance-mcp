<div align="center">

# Cra Compliance MCP

**MCP server for cra compliance mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-cra-compliance-mcp)](https://pypi.org/project/meok-cra-compliance-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Cra Compliance MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `classify_product` | Classify a product with digital elements (PDE) into its CRA class (default/I/II/ |
| `audit_annex_i` | Audit Annex I essential cybersecurity requirements (both Part 1 product properti |
| `sbom_skeleton` | Generate a minimal CycloneDX-style SBOM skeleton required for CRA Article 13. |
| `vulnerability_reporting_readiness` | Check readiness for the Sep 2026 mandatory reporting of exploited vulnerabilitie |
| `conformity_assessment_roadmap` | Produce a conformity assessment roadmap for CE marking your product under CRA. |
| `enforcement_status` | Current CRA enforcement timeline + key deadlines. |
| `sign_cra_attestation` | Generate a cryptographically signed CRA (Cyber Resilience Act) compliance attest |

## Installation

```bash
pip install meok-cra-compliance-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "cra-compliance-mcp": {
      "command": "python",
      "args": ["-m", "meok_cra_compliance_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 7 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)

<!-- mcp-name: io.github.CSOAI-ORG/cra-compliance-mcp -->
