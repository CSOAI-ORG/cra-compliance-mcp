[![cra-compliance-mcp MCP server](https://glama.ai/mcp/servers/CSOAI-ORG/cra-compliance-mcp/badges/score.svg)](https://glama.ai/mcp/servers/CSOAI-ORG/cra-compliance-mcp)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-Published-green)](https://registry.modelcontextprotocol.io)
[![PyPI](https://img.shields.io/pypi/v/cra-compliance-mcp)](https://pypi.org/project/cra-compliance-mcp/)

[![cra-compliance-mcp MCP server](https://glama.ai/mcp/servers/CSOAI-ORG/cra-compliance-mcp/badges/card.svg)](https://glama.ai/mcp/servers/CSOAI-ORG/cra-compliance-mcp)

<div align="center">

[![PyPI](https://img.shields.io/pypi/v/cra-compliance-mcp)](https://pypi.org/project/cra-compliance-mcp/)
[![Downloads](https://img.shields.io/pypi/dm/cra-compliance-mcp)](https://pypi.org/project/cra-compliance-mcp/)
[![GitHub stars](https://img.shields.io/github/stars/CSOAI-ORG/cra-compliance-mcp)](https://github.com/CSOAI-ORG/cra-compliance-mcp/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

# CRA Compliance MCP

**Automate EU Cyber Resilience Act (Regulation 2024/2847) compliance for products with digital elements.**

Manufacturers · Importers · Distributors · Open-source stewards

Full applicability: **11 December 2027**. Penalties: up to EUR 15M or 2.5% of global turnover.

[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-224+_servers-purple)](https://meok.ai)

[Install](#install) · [Tools](#tools) · [Pricing](#pricing)

</div>

---

## Why This Exists

The CRA applies to every product with digital elements sold in the EU — software, IoT devices, industrial controllers, SaaS platforms. Manufacturers must ensure security by design, handle vulnerabilities within 24 hours, and maintain technical documentation for 10 years. Open-source projects used commercially have a new "open-source steward" category with lighter obligations.

This MCP classifies your product against CRA categories, assesses essential security requirements, checks vulnerability handling processes, and generates the conformity documentation.

## Install

```bash
pip install cra-compliance-mcp
```

## Tools

| Tool | CRA Reference | What it does |
|------|-------------|-------------|
| `classify_product` | Art 6-8 | Product category classification (default/important/critical) |
| `assess_security_requirements` | Annex I | Essential cybersecurity requirements check |
| `check_vulnerability_handling` | Art 14 | 24-hour vulnerability disclosure readiness |
| `generate_documentation` | Annex VII | Technical documentation generator |
| `assess_supply_chain` | Art 13 | Software bill of materials + dependency audit |
| `check_open_source_obligations` | Art 25 | Open-source steward obligations |
| `run_full_audit` | All | Complete CRA readiness assessment |
| `sign_attestation` | — | HMAC-SHA256 signed compliance certificate |

## Key Dates

| Milestone | Date |
|-----------|------|
| Entry into force | 10 December 2024 |
| Vulnerability reporting obligations | 11 September 2026 |
| Full applicability | **11 December 2027** |

## Pricing

| Tier | Price | What you get |
|------|-------|-------------|
| **Free** | £0 | 10 calls/day |
| **Pro** | £199/mo | Unlimited + HMAC-signed attestations |
| **Enterprise** | £1,499/mo | Multi-tenant + co-branded reports |

[Subscribe to Pro](https://buy.stripe.com/14A4gB3K4eUWgYR56o8k836) · [Enterprise](https://buy.stripe.com/4gM9AV80kaEG0ZT42k8k837)

## Attestation API

```
POST https://meok-attestation-api.vercel.app/sign
GET  https://meok-attestation-api.vercel.app/verify/{cert_id}
```

Also see: [CRA Annex IV Classifier MCP](https://github.com/CSOAI-ORG/meok-cra-annex-iv-classifier-mcp) for detailed Annex IV essential requirements.

## Links

- Website: [meok.ai](https://meok.ai)
- All MCP servers: [meok.ai/labs/mcp/servers](https://meok.ai/labs/mcp/servers)
- Enterprise support: nicholas@csoai.org

## License

MIT
<!-- mcp-name: io.github.CSOAI-ORG/cra-compliance-mcp -->
