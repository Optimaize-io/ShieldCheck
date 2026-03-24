"""
Markdown Report Generator
Generates professional markdown reports from lead scan results.
"""

from typing import List, Optional
from datetime import datetime
import json
from pathlib import Path

from scoring.scorer import LeadScore, LeadTier


class MarkdownReportGenerator:
    """
    Generates professional markdown reports from lead scan results.
    The report IS the product - formatting matters for Nomios.
    """
    
    def __init__(self):
        self.generated_at = datetime.now()
    
    def generate(self, leads: List[LeadScore], output_path: Optional[str] = None) -> str:
        """
        Generate a complete markdown report.
        
        Args:
            leads: List of scored leads
            output_path: Optional path to write report
            
        Returns:
            Complete markdown report as string
        """
        # Sort leads by score (lowest/worst first = hottest leads)
        sorted_leads = sorted(leads, key=lambda x: x.total_score)
        
        # Count by tier
        hot_count = sum(1 for l in leads if l.tier == LeadTier.HOT)
        warm_count = sum(1 for l in leads if l.tier == LeadTier.WARM)
        cool_count = sum(1 for l in leads if l.tier == LeadTier.COOL)
        
        # Build report sections
        sections = [
            self._header(len(leads)),
            self._executive_summary(leads, hot_count, warm_count, cool_count),
            self._ranking_table(sorted_leads),
            self._detailed_reports(sorted_leads),
            self._methodology(),
            self._scale_up_pitch(len(leads)),
        ]
        
        report = "\n\n".join(sections)
        
        # Write to file if path provided
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
        
        return report
    
    def generate_json(self, leads: List[LeadScore], output_path: str) -> None:
        """
        Generate JSON data file with all results.
        
        Args:
            leads: List of scored leads
            output_path: Path to write JSON file
        """
        data = {
            "generated_at": self.generated_at.isoformat(),
            "total_companies": len(leads),
            "summary": {
                "hot_leads": sum(1 for l in leads if l.tier == LeadTier.HOT),
                "warm_leads": sum(1 for l in leads if l.tier == LeadTier.WARM),
                "cool_leads": sum(1 for l in leads if l.tier == LeadTier.COOL),
            },
            "leads": [lead.to_dict() for lead in sorted(leads, key=lambda x: x.total_score)]
        }
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def _header(self, company_count: int) -> str:
        """Generate report header."""
        date_str = self.generated_at.strftime("%Y-%m-%d %H:%M")
        
        return f"""# 🔍 Lead Scout Report
## NIS2 Compliance & Security Posture Analysis

**Generated:** {date_str}  
**Companies Analyzed:** {company_count}  
**Powered by:** Polderbase Lead Scout

---"""
    
    def _executive_summary(
        self, 
        leads: List[LeadScore], 
        hot: int, 
        warm: int, 
        cool: int
    ) -> str:
        """Generate executive summary."""
        total = len(leads)
        
        # Find the most common gaps
        gap_counts = {}
        for lead in leads:
            for gap in lead.key_gaps:
                gap_type = gap.split(' - ')[0].split(':')[0][:40]
                gap_counts[gap_type] = gap_counts.get(gap_type, 0) + 1
        
        top_gaps = sorted(gap_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # NIS2 coverage
        nis2_covered = sum(1 for l in leads if l.nis2_covered)
        critical_priority = sum(1 for l in leads if l.compliance_priority == "CRITICAL")
        
        summary = f"""## 📊 Executive Summary

### Lead Distribution

| Tier | Count | Percentage | Description |
|------|-------|------------|-------------|
| 🔴 **HOT** | {hot} | {hot/total*100:.0f}% | Major gaps everywhere. Highest priority. |
| 🟠 **WARM** | {warm} | {warm/total*100:.0f}% | Notable gaps. Good opportunities. |
| 🟢 **COOL** | {cool} | {cool/total*100:.0f}% | Reasonably prepared. Lower priority. |

### NIS2 Compliance Outlook

- **{nis2_covered}** companies likely covered by NIS2/Cyberbeveiligingswet
- **{critical_priority}** with CRITICAL compliance priority (large essential entities)
- Dutch implementation deadline: **Q2 2026**

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
        """Generate ranking table sorted by score (hottest first)."""
        table = """## 🏆 Lead Rankings

> **Note:** Lower scores indicate more security gaps = higher priority leads

| Rank | Company | Sector | Employees | Score | Tier | Key Gap |
|------|---------|--------|-----------|-------|------|---------|
"""
        for i, lead in enumerate(leads, 1):
            # Get first key gap or default message
            key_gap = lead.key_gaps[0][:40] + "..." if lead.key_gaps and len(lead.key_gaps[0]) > 40 else (lead.key_gaps[0] if lead.key_gaps else "No critical gaps")
            
            table += f"| {i} | **{lead.company_name}** | {lead.sector[:20]} | {lead.employees:,} | {lead.total_score:.0f}/10 | {lead.tier.value} | {key_gap} |\n"
        
        return table
    
    def _detailed_reports(self, leads: List[LeadScore]) -> str:
        """Generate detailed per-company reports."""
        details = "## 📋 Detailed Company Reports\n\n"
        details += "> Sorted by priority (highest first)\n\n"
        
        for lead in leads:
            details += self._company_report(lead)
            details += "\n---\n\n"
        
        return details
    
    def _company_report(self, lead: LeadScore) -> str:
        """Generate detailed report for one company."""
        report = f"""### {lead.tier.value} {lead.company_name}

**Domain:** `{lead.domain}`  
**Sector:** {lead.sector}  
**Employees:** ~{lead.employees:,}  
**Overall Score:** {lead.total_score:.0f}/10  

"""
        # NIS2 status
        if lead.nis2_covered:
            report += f"""**⚠️ NIS2 Status:** Likely covered as **{lead.nis2_entity_type}** entity in **{lead.nis2_sector}**  
**Compliance Priority:** {lead.compliance_priority}

"""
        
        # Score breakdown
        report += """#### Score Breakdown

| Dimension | Score | Assessment |
|-----------|-------|------------|
"""
        dimensions = [
            ("Email Security", lead.email_security),
            ("Technical Hygiene", lead.technical_hygiene),
            ("TLS Certificate", lead.tls_certificate),
            ("Security Communication", lead.security_communication),
            ("NIS2 Readiness", lead.nis2_readiness),
        ]
        
        for name, dim in dimensions:
            if dim:
                report += f"| {dim.emoji} {name} | {dim.score}/2 | {dim.description} |\n"
            else:
                report += f"| ⚪ {name} | -/2 | Not checked |\n"
        
        # Key findings
        if lead.key_gaps:
            report += "\n#### 🚨 Key Findings\n\n"
            for gap in lead.key_gaps:
                report += f"- {gap}\n"
        
        # Detailed findings from scans
        report += "\n#### 📝 Technical Details\n\n"
        
        # DNS findings
        if lead.dns_result and lead.dns_result.findings:
            report += "**Email Security (DNS):**\n"
            for finding in lead.dns_result.findings:
                report += f"  {finding}\n"
            report += "\n"
        
        # Shodan findings
        if lead.shodan_result and lead.shodan_result.findings:
            report += "**Internet Exposure (Shodan):**\n"
            for finding in lead.shodan_result.findings[:6]:  # Limit to 6
                report += f"  {finding}\n"
            report += "\n"
        
        # SSL findings
        if lead.ssl_result and lead.ssl_result.findings:
            report += "**TLS/SSL Certificate:**\n"
            for finding in lead.ssl_result.findings:
                report += f"  {finding}\n"
            report += "\n"
        
        # Website findings
        if lead.website_result and lead.website_result.findings:
            report += "**Website Analysis:**\n"
            for finding in lead.website_result.findings[:5]:  # Limit to 5
                report += f"  {finding}\n"
            report += "\n"
        
        # Sales angles - THE MAGIC SECTION
        if lead.sales_angles:
            report += "#### 💼 Recommended Sales Approach\n\n"
            for i, angle in enumerate(lead.sales_angles, 1):
                report += f"{i}. {angle}\n\n"
        
        return report
    
    def _methodology(self) -> str:
        """Generate methodology section."""
        return """## 🔬 Methodology

### About This Report

This report was generated using **Open Source Intelligence (OSINT)** techniques only. 
All information was gathered from publicly accessible sources:

1. **DNS Record Analysis** - SPF, DMARC, and DKIM records that define email authentication
2. **Internet Exposure Check** - Shodan InternetDB for open ports and known vulnerabilities
3. **SSL/TLS Validation** - Certificate validity, expiry, and protocol support
4. **Website Content Analysis** - Public pages scanned for security messaging and NIS2 awareness

### Legal & Ethical Notes

✅ **No hacking or unauthorized access** - Only public information was used  
✅ **No login attempts** - No authentication was attempted  
✅ **Rate-limited requests** - Polite scanning with delays between checks  
✅ **Identifiable User-Agent** - All requests identified as security research  

### Scoring Logic

Each company is scored on 5 dimensions (0-2 points each, total 0-10):

| Score | Meaning |
|-------|---------|
| 0 | Poor/missing protection - significant gap |
| 1 | Partial protection - room for improvement |
| 2 | Good protection - meets best practice |

**Lead Tiers:**
- 🔴 **HOT (0-3):** Multiple critical gaps. Highest priority.
- 🟠 **WARM (4-6):** Notable gaps exist. Good opportunity.
- 🟢 **COOL (7-10):** Well-prepared. Maintenance opportunity.

### NIS2 Classification

Companies are classified based on the EU NIS2 Directive and the Dutch 
Cyberbeveiligingswet implementation. Sectors are identified from:
- Stated company sector
- Website content analysis for sector keywords

Size thresholds (generally 50+ employees for coverage) are applied based 
on provided employee estimates.
"""
    
    def _scale_up_pitch(self, company_count: int) -> str:
        """Generate scale-up pitch for Nomios."""
        return f"""## 🚀 Scale-Up Opportunity

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

### NIS2 Deadline: Q2 2026

Thousands of Dutch companies are affected but unprepared. This tool finds the ones 
most likely to need Nomios's services - **before your competitors find them.**

---

*Report generated by Polderbase Lead Scout*  
*Questions? Contact us to discuss scaling this for Nomios.*
"""
