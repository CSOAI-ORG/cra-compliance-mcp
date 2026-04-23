# CRA Compliance MCP

**The only MCP server that automates EU Cyber Resilience Act (CRA, Regulation 2024/2847) compliance** for manufacturers, importers, and distributors of products with digital elements.

Built by [MEOK AI Labs](https://meok.ai). Pairs with our DORA, NIS2, EU AI Act, and ISO MCPs.

## What it does

- **Classify any product** into CRA class (default / Class I / Class II / Critical)
- **Audit Annex I essential requirements** (both product-property Part 1 and vulnerability-handling Part 2)
- **Generate CycloneDX SBOM skeleton** (Article 13 + Annex I 2.1 mandatory)
- **Assess vulnerability-reporting readiness** for Sep 2026 mandatory reporting to ENISA
- **Produce conformity assessment roadmap** with CE marking path + timeline + cost estimate
- **Track enforcement timeline** — 3 critical dates between now and Dec 2027

## Install

```bash
pip install cra-compliance-mcp
```

## Use with Claude Desktop

```json
{
  "mcpServers": {
    "cra": { "command": "cra-compliance-mcp" }
  }
}
```

## Why it matters

- **Enforcement dates locked in**: 11 Sep 2026 (reporting) → 11 Jun 2027 (vuln handling) → 11 Dec 2027 (full)
- **Penalties up to €15M or 2.5% of global turnover** for Annex I violations
- **ALL products with digital elements** sold on EU market in scope — IoT, software, SaaS, firmware, mobile apps
- **ENISA single reporting platform** launching 2026 — requires 24h / 72h / 1-month timeline
- **CE marking mandatory** from Dec 2027 — no CRA compliance = no EU market

## Tiers

- **Free** — 10 calls/day, classification, Annex I audit, SBOM skeleton
- **Pro (£199/mo)** — unlimited, signed attestations, full SBOM scanner, notified-body handoff pack
- **Team (£499/mo)** — multi-product, consolidated dashboard, cross-CRA/NIS2/DORA crosswalk
- **Enterprise (£1,499/mo)** — SSO, SLA, co-branded Trust Center push, Annex II tech doc generator
- **48h written assessment (£5,000)** — vs £20–80k Big-4 gap assessments

## Legal basis

Regulation (EU) 2024/2847 (Cyber Resilience Act). Commission Delegated and Implementing acts pending for Annex III/IV expansion and reporting technical formats. Automated self-assessment — not a substitute for a notified body conformity assessment.

## License

MIT. MEOK AI Labs, 2026.
