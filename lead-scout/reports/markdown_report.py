"""
Markdown Report Generator
Generates professional markdown reports from lead scan results.
"""

from datetime import datetime
import json
from pathlib import Path
from typing import List, Optional

from scoring.scorer import LeadScore, LeadTier


class MarkdownReportGenerator:
    """
    Generates professional markdown reports from lead scan results.
    The report IS the product - formatting matters for Nomios.
    """

    def __init__(self):
        self.generated_at = datetime.now()

    def generate(self, leads: List[LeadScore], output_path: Optional[str] = None) -> str:
        sorted_leads = sorted(leads, key=lambda x: x.total_score)

        hot_count = sum(1 for l in leads if l.tier == LeadTier.HOT)
        warm_count = sum(1 for l in leads if l.tier == LeadTier.WARM)
        cool_count = sum(1 for l in leads if l.tier == LeadTier.COOL)

        sections = [
            self._header(len(leads)),
            self._executive_summary(leads, hot_count, warm_count, cool_count),
            self._ranking_table(sorted_leads),
            self._detailed_reports(sorted_leads),
            self._methodology(),
            self._scale_up_pitch(len(leads)),
        ]

        report = "\n\n".join(sections)
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as handle:
                handle.write(report)
        return report

    def generate_json(self, leads: List[LeadScore], output_path: str) -> None:
        data = {
            "generated_at": self.generated_at.isoformat(),
            "total_companies": len(leads),
            "summary": {
                "hot_leads": sum(1 for l in leads if l.tier == LeadTier.HOT),
                "warm_leads": sum(1 for l in leads if l.tier == LeadTier.WARM),
                "cool_leads": sum(1 for l in leads if l.tier == LeadTier.COOL),
            },
            "leads": [lead.to_dict() for lead in sorted(leads, key=lambda x: x.total_score)],
        }

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)

    def _header(self, company_count: int) -> str:
        date_str = self.generated_at.strftime("%Y-%m-%d %H:%M")
        return f"""# Lead Scout Report
## Security Posture Analysis

**Generated:** {date_str}  
**Companies Analyzed:** {company_count}  
**Powered by:** Polderbase Lead Scout

---"""

    def _executive_summary(
        self, leads: List[LeadScore], hot: int, warm: int, cool: int
    ) -> str:
        total = len(leads)
        gap_counts = {}
        for lead in leads:
            for gap in lead.key_gaps:
                gap_type = gap.split(" - ")[0].split(":")[0][:40]
                gap_counts[gap_type] = gap_counts.get(gap_type, 0) + 1

        top_gaps = sorted(gap_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        summary = f"""## Executive Summary

### Lead Distribution

| Tier | Count | Percentage | Description |
|------|-------|------------|-------------|
| HOT | {hot} | {hot/total*100:.0f}% | Major gaps everywhere. Highest priority. |
| WARM | {warm} | {warm/total*100:.0f}% | Notable gaps. Good opportunities. |
| COOL | {cool} | {cool/total*100:.0f}% | Reasonably prepared. Lower priority. |

### Most Common Security Gaps

"""
        if top_gaps:
            for gap, count in top_gaps:
                pct = count / total * 100
                summary += f"- **{gap}** - {count} companies ({pct:.0f}%)\n"
        else:
            summary += "- No significant common gaps identified\n"
        return summary

    def _ranking_table(self, leads: List[LeadScore]) -> str:
        table = """## Lead Rankings

> **Note:** Lower scores indicate more security gaps = higher priority leads

| Rank | Company | Sector | Employees | Score | Tier | Key Gap |
|------|---------|--------|-----------|-------|------|---------|
"""
        for i, lead in enumerate(leads, 1):
            key_gap = (
                lead.key_gaps[0][:40] + "..."
                if lead.key_gaps and len(lead.key_gaps[0]) > 40
                else (lead.key_gaps[0] if lead.key_gaps else "No critical gaps")
            )
            table += (
                f"| {i} | **{lead.company_name}** | {lead.sector[:20]} | "
                f"{lead.employees:,} | {lead.total_score:.1f}/{lead.max_score:.0f} | "
                f"{lead.tier.value} | {key_gap} |\n"
            )
        return table

    def _detailed_reports(self, leads: List[LeadScore]) -> str:
        details = "## Detailed Company Reports\n\n> Sorted by priority (highest first)\n\n"
        for lead in leads:
            details += self._company_report(lead)
            details += "\n---\n\n"
        return details

    def _company_report(self, lead: LeadScore) -> str:
        report = f"""### {lead.tier.value} {lead.company_name}

**Domain:** `{lead.domain}`  
**Sector:** {lead.sector}  
**Employees:** ~{lead.employees:,}  
**Overall Score:** {lead.total_score:.1f}/{lead.max_score:.0f}  

"""
        report += """#### Score Breakdown

| Dimension | Score | Assessment |
|-----------|-------|------------|
"""
        dimensions = [
            ("Email Security", lead.email_security),
            ("Technical Hygiene", lead.technical_hygiene),
            ("TLS Certificate", lead.tls_certificate),
            ("HTTP Headers", lead.http_headers),
            ("Cookie Compliance", lead.cookie_compliance),
            ("Attack Surface", lead.attack_surface),
            ("Tech Stack", lead.tech_stack),
            ("Admin Exposure", lead.admin_panel),
            ("Security Hiring", lead.security_hiring),
            ("Security Governance", lead.security_governance),
            ("Security Communication", lead.security_communication),
        ]

        for name, dim in dimensions:
            if dim:
                report += f"| {name} | {dim.display_score()} | {dim.description} |\n"
            else:
                report += f"| {name} | N/A | Not analyzed |\n"

        if lead.key_gaps:
            report += "\n#### Key Findings\n\n"
            for gap in lead.key_gaps:
                report += f"- {gap}\n"

        report += "\n#### Detailed Findings\n\n"
        all_dims = [
            lead.email_security,
            lead.technical_hygiene,
            lead.tls_certificate,
            lead.http_headers,
            lead.cookie_compliance,
            lead.attack_surface,
            lead.tech_stack,
            lead.admin_panel,
            lead.security_hiring,
            lead.security_governance,
            lead.security_communication,
        ]
        for dim in all_dims:
            if not dim or not dim.analyzed or not dim.missing:
                continue
            report += f"**{dim.name}:**\n"
            for item in dim.missing:
                report += f"- {item}\n"
            if dim.risks:
                report += f"- Risk: {dim.risks[0]}\n"
            report += "\n"

        if lead.sales_angles:
            report += "#### Recommended Sales Approach\n\n"
            for i, angle in enumerate(lead.sales_angles, 1):
                report += f"{i}. {angle}\n\n"

        return report

    def _methodology(self) -> str:
        return """## Methodology

### About This Report

This report was generated using **Open Source Intelligence (OSINT)** techniques only. 
All information was gathered from publicly accessible sources:

1. **DNS Record Analysis** - SPF, DMARC, and DKIM records that define email authentication
2. **Internet Exposure Check** - Shodan InternetDB for open ports and known vulnerabilities
3. **SSL/TLS Validation** - Certificate validity, expiry, and protocol support
4. **Website Content Analysis** - Public pages scanned for security messaging and trust signals

### Legal & Ethical Notes

- **No hacking or unauthorized access** - Only public information was used  
- **No login attempts** - No authentication was attempted  
- **Rate-limited requests** - Polite scanning with delays between checks  
- **Identifiable User-Agent** - All requests identified as security research  

### Scoring Logic

Each company is assessed across the lead-generation dimensions that matter for outward security posture. 
The report shows scores as **`score/max_score`** per dimension.

**Lead tiers are percentage-based (lower score = hotter lead):**
- **HOT:** <= 45% of max score
- **WARM:** <= 75% of max score
- **COOL:** > 75% of max score
"""

    def _scale_up_pitch(self, company_count: int) -> str:
        return f"""## Scale-Up Opportunity

This report analyzed **{company_count} companies** to demonstrate our capabilities.

### Imagine This at Scale

| Scale | Companies | Estimated HOT Leads |
|-------|-----------|---------------------|
| This Demo | {company_count} | ~{int(company_count * 0.3)} |
| Small Campaign | 500 | ~150 |
| Medium Campaign | 2,000 | ~600 |
| Full Dutch Market | 10,000+ | ~3,000+ |

### What We Can Do

1. **Sector-Specific Scans** - Target all Dutch energy companies, healthcare providers, etc.
2. **Continuous Monitoring** - Weekly rescans to catch certificate expirations and new CVEs
3. **CRM Integration** - Direct feed into your sales pipeline
4. **Custom Scoring** - Tune the algorithm for your ideal customer profile
5. **Dashboard Access** - Real-time view of lead pipeline

Thousands of Dutch companies show visible security gaps. This tool finds the ones 
most likely to need Nomios's services - **before your competitors find them.**

---

*Report generated by Polderbase Lead Scout*  
*Questions? Contact us to discuss scaling this for Nomios.*
"""
