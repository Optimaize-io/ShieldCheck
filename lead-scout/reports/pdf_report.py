"""
PDF Report Generator - Professional Security Assessment Reports
Generates individual company PDF reports with professional business styling.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path
import io
import os
import json

# ReportLab imports
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm, cm, inch
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        PageBreak,
        Image,
        HRFlowable,
        ListFlowable,
        ListItem,
        KeepTogether,
        Flowable,
        Preformatted,
    )
    from reportlab.graphics.shapes import Drawing, Rect, String, Line
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from scoring.scorer import LeadScore, LeadTier


# Professional color scheme
class Colors:
    """Professional color palette for reports."""

    PRIMARY = colors.HexColor("#1a365d")  # Deep blue
    SECONDARY = colors.HexColor("#2d3748")  # Dark slate
    ACCENT = colors.HexColor("#3182ce")  # Bright blue
    SUCCESS = colors.HexColor("#38a169")  # Green
    WARNING = colors.HexColor("#e67e22")  # Orange
    DANGER = colors.HexColor("#e53e3e")  # Red
    TEXT = colors.HexColor("#2d3748")  # Dark gray text
    TEXT_LIGHT = colors.HexColor("#718096")  # Light gray text
    BACKGROUND = colors.HexColor("#f7fafc")  # Light background
    WHITE = colors.white
    BLACK = colors.black


class ScoreGauge(Flowable):
    """Custom flowable for score visualization."""

    def __init__(
        self,
        score: float,
        max_score: float = 24.0,
        width: float = 150,
        height: float = 80,
    ):
        Flowable.__init__(self)
        self.score = score
        self.max_score = max_score
        self.width = width
        self.height = height

    def draw(self):
        """Draw the score gauge."""
        # Determine color based on score
        percentage = self.score / self.max_score
        if percentage <= 0.33:
            color = Colors.DANGER
            label = "HIGH RISK"
        elif percentage <= 0.67:
            color = Colors.WARNING
            label = "MODERATE RISK"
        else:
            color = Colors.SUCCESS
            label = "LOW RISK"

        # Draw background bar
        self.canv.setFillColor(colors.HexColor("#e2e8f0"))
        self.canv.roundRect(0, 30, self.width, 20, 5, fill=1, stroke=0)

        # Draw filled portion
        filled_width = self.width * percentage
        self.canv.setFillColor(color)
        self.canv.roundRect(0, 30, filled_width, 20, 5, fill=1, stroke=0)

        # Draw score text
        self.canv.setFillColor(Colors.TEXT)
        self.canv.setFont("Helvetica-Bold", 24)
        self.canv.drawString(0, 0, f"{self.score:.1f}/{self.max_score:.0f}")

        # Draw label
        self.canv.setFont("Helvetica-Bold", 10)
        self.canv.setFillColor(color)
        self.canv.drawString(self.width + 10, 35, label)


class PDFReportGenerator:
    """
    Generates professional PDF security assessment reports.
    """

    def __init__(self):
        if not REPORTLAB_AVAILABLE:
            raise ImportError(
                "ReportLab is required for PDF generation. "
                "Install with: pip install reportlab"
            )
        self.styles = self._create_styles()
        self.generated_at = datetime.now()

    def _create_styles(self) -> Dict[str, ParagraphStyle]:
        """Create custom paragraph styles."""
        base_styles = getSampleStyleSheet()

        styles = {
            "Title": ParagraphStyle(
                "CustomTitle",
                parent=base_styles["Title"],
                fontSize=28,
                textColor=Colors.PRIMARY,
                spaceAfter=20,
                alignment=TA_LEFT,
                fontName="Helvetica-Bold",
            ),
            "Subtitle": ParagraphStyle(
                "CustomSubtitle",
                parent=base_styles["Heading2"],
                fontSize=14,
                textColor=Colors.TEXT_LIGHT,
                spaceAfter=30,
                alignment=TA_LEFT,
            ),
            "Heading1": ParagraphStyle(
                "CustomH1",
                parent=base_styles["Heading1"],
                fontSize=18,
                textColor=Colors.PRIMARY,
                spaceBefore=20,
                spaceAfter=12,
                fontName="Helvetica-Bold",
                borderPadding=(0, 0, 5, 0),
            ),
            "Heading2": ParagraphStyle(
                "CustomH2",
                parent=base_styles["Heading2"],
                fontSize=14,
                textColor=Colors.SECONDARY,
                spaceBefore=15,
                spaceAfter=8,
                fontName="Helvetica-Bold",
            ),
            "Heading3": ParagraphStyle(
                "CustomH3",
                parent=base_styles["Heading3"],
                fontSize=12,
                textColor=Colors.TEXT,
                spaceBefore=10,
                spaceAfter=6,
                fontName="Helvetica-Bold",
            ),
            "Body": ParagraphStyle(
                "CustomBody",
                parent=base_styles["Normal"],
                fontSize=10,
                textColor=Colors.TEXT,
                leading=14,
                alignment=TA_JUSTIFY,
                spaceAfter=8,
            ),
            "BodySmall": ParagraphStyle(
                "CustomBodySmall",
                parent=base_styles["Normal"],
                fontSize=9,
                textColor=Colors.TEXT_LIGHT,
                leading=12,
                spaceAfter=6,
            ),
            "Finding": ParagraphStyle(
                "Finding",
                parent=base_styles["Normal"],
                fontSize=10,
                textColor=Colors.TEXT,
                leading=14,
                leftIndent=15,
                spaceAfter=4,
            ),
            "KeyGap": ParagraphStyle(
                "KeyGap",
                parent=base_styles["Normal"],
                fontSize=10,
                textColor=Colors.DANGER,
                leading=14,
                leftIndent=15,
                spaceAfter=4,
                fontName="Helvetica-Bold",
            ),
            "Recommendation": ParagraphStyle(
                "Recommendation",
                parent=base_styles["Normal"],
                fontSize=10,
                textColor=Colors.ACCENT,
                leading=14,
                leftIndent=15,
                spaceAfter=4,
            ),
            "CodeBlock": ParagraphStyle(
                "CodeBlock",
                parent=base_styles["Normal"],
                fontName="Courier",
                fontSize=8,
                leading=10,
                textColor=Colors.SECONDARY,
                backColor=colors.HexColor("#f7fafc"),
                borderPadding=(6, 6, 6, 6),
                spaceBefore=6,
                spaceAfter=10,
            ),
            "Footer": ParagraphStyle(
                "Footer",
                parent=base_styles["Normal"],
                fontSize=8,
                textColor=Colors.TEXT_LIGHT,
                alignment=TA_CENTER,
            ),
        }

        return styles

    def generate(self, lead: LeadScore, output_path: str) -> str:
        """
        Generate a PDF report for a single company.

        Args:
            lead: LeadScore object with scan results
            output_path: Path to save PDF file

        Returns:
            Path to generated PDF
        """
        # Ensure output directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        # Create document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )

        # Keep current lead for metadata/header/footer
        self._current_lead = lead

        # Build story
        story = self._build_story(lead)

        # Build PDF with header/footer
        doc.build(
            story,
            onFirstPage=self._add_header_footer,
            onLaterPages=self._add_header_footer,
        )

        return output_path

    def _add_header_footer(self, canvas, doc):
        """Add header and footer to each page."""
        canvas.saveState()

        # PDF metadata (prevents "(anonymous)" title in many viewers)
        lead = getattr(self, "_current_lead", None)
        company = (getattr(lead, "company_name", None) or "").strip() if lead else ""
        domain = (getattr(lead, "domain", None) or "").strip() if lead else ""
        title = f"Security Assessment Report - {company or domain or 'Lead Scout'}"
        canvas.setTitle(title)
        canvas.setAuthor("Lead Scout")
        if domain:
            canvas.setSubject(f"Domain: {domain}")

        # Header line
        canvas.setStrokeColor(Colors.PRIMARY)
        canvas.setLineWidth(2)
        canvas.line(2 * cm, A4[1] - 1.5 * cm, A4[0] - 2 * cm, A4[1] - 1.5 * cm)

        # Footer
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(Colors.TEXT_LIGHT)
        footer_text = f"Security Assessment Report | Generated {self.generated_at.strftime('%Y-%m-%d %H:%M')} | Confidential"
        canvas.drawCentredString(A4[0] / 2, 1 * cm, footer_text)

        # Page number
        page_num = canvas.getPageNumber()
        canvas.drawRightString(A4[0] - 2 * cm, 1 * cm, f"Page {page_num}")

        canvas.restoreState()

    def _build_story(self, lead: LeadScore) -> List:
        """Build the PDF content story."""
        story = []

        # Cover page
        story.extend(self._build_cover_page(lead))
        story.append(PageBreak())

        # Executive Summary
        story.extend(self._build_executive_summary(lead))
        story.append(PageBreak())

        # Detailed Findings
        story.extend(self._build_detailed_findings(lead))

        # Recommendations
        story.extend(self._build_recommendations(lead))

        # Technical Appendix
        story.append(PageBreak())
        story.extend(self._build_technical_appendix(lead))

        return story

    def _build_cover_page(self, lead: LeadScore) -> List:
        """Build the cover page."""
        elements = []

        # Large spacer for visual balance
        elements.append(Spacer(1, 3 * cm))

        # Company name as main title
        elements.append(Paragraph(f"Security Assessment Report", self.styles["Title"]))

        elements.append(Spacer(1, 0.5 * cm))

        # Company name
        elements.append(
            Paragraph(
                f"<b>{lead.company_name}</b>",
                ParagraphStyle(
                    "CompanyName", fontSize=24, textColor=Colors.ACCENT, spaceAfter=10
                ),
            )
        )

        # Domain
        elements.append(Paragraph(f"{lead.domain}", self.styles["Subtitle"]))

        elements.append(Spacer(1, 1 * cm))

        # Horizontal rule
        elements.append(
            HRFlowable(
                width="100%", thickness=2, color=Colors.PRIMARY, spaceAfter=1 * cm
            )
        )

        # Company info table
        info_data = [
            ["Sector:", lead.sector],
            ["Assessment Date:", self.generated_at.strftime("%B %d, %Y")],
        ]

        if lead.nis2_covered:
            info_data.append(
                ["NIS2 Status:", f"Covered ({lead.nis2_entity_type or 'Entity'})"]
            )

        info_table = Table(info_data, colWidths=[4 * cm, 8 * cm])
        info_table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 11),
                    ("TEXTCOLOR", (0, 0), (0, -1), Colors.TEXT_LIGHT),
                    ("TEXTCOLOR", (1, 0), (1, -1), Colors.TEXT),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("ALIGN", (0, 0), (0, -1), "RIGHT"),
                    ("ALIGN", (1, 0), (1, -1), "LEFT"),
                ]
            )
        )
        elements.append(info_table)

        elements.append(Spacer(1, 2 * cm))

        # Overall score box
        tier_color = self._get_tier_color(lead.tier)
        tier_label = (
            lead.tier.value.replace("🔴 ", "").replace("🟠 ", "").replace("🟢 ", "")
        )

        score_data = [
            [
                Paragraph(
                    f"<b>Overall Security Score</b>",
                    ParagraphStyle("ScoreLabel", fontSize=12, textColor=Colors.WHITE),
                ),
            ],
            [
                Paragraph(
                    f"<b>{lead.total_score:.1f}</b> / {lead.max_score:.0f}",
                    ParagraphStyle(
                        "ScoreValue",
                        fontSize=36,
                        textColor=Colors.WHITE,
                        alignment=TA_CENTER,
                    ),
                ),
            ],
            [
                Paragraph(
                    f"<b>{tier_label}</b>",
                    ParagraphStyle(
                        "TierLabel",
                        fontSize=14,
                        textColor=Colors.WHITE,
                        alignment=TA_CENTER,
                    ),
                ),
            ],
        ]

        score_table = Table(score_data, colWidths=[8 * cm])
        score_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), tier_color),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 15),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 15),
                    ("LEFTPADDING", (0, 0), (-1, -1), 20),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 20),
                    ("ROUNDEDCORNERS", [10, 10, 10, 10]),
                ]
            )
        )
        elements.append(score_table)

        elements.append(Spacer(1, 2 * cm))

        # Disclaimer
        elements.append(
            Paragraph(
                "<i>This report is based on publicly available information and passive scanning techniques. "
                "No active penetration testing or vulnerability exploitation was performed. "
                "This assessment is intended for informational purposes only.</i>",
                self.styles["BodySmall"],
            )
        )

        return elements

    def _build_executive_summary(self, lead: LeadScore) -> List:
        """Build the executive summary section."""
        elements = []

        elements.append(Paragraph("Executive Summary", self.styles["Heading1"]))
        elements.append(
            HRFlowable(
                width="100%", thickness=1, color=Colors.ACCENT, spaceAfter=0.5 * cm
            )
        )

        # Summary paragraph
        tier_text = self._get_tier_description(lead.tier)
        elements.append(
            Paragraph(
                f"This security assessment of <b>{lead.company_name}</b> ({lead.domain}) identified "
                f"<b>{lead.findings_count} findings</b> across twelve key security dimensions. "
                f"The overall security posture is rated as <b>{tier_text}</b> with a score of "
                f"<b>{lead.total_score:.1f}/{lead.max_score:.0f}</b>.",
                self.styles["Body"],
            )
        )

        # NIS2 context if applicable
        if lead.nis2_covered:
            elements.append(Spacer(1, 0.5 * cm))
            elements.append(
                Paragraph(
                    f"⚠️ <b>NIS2 Compliance Note:</b> Based on the sector ({lead.sector}) and company size, "
                    f"{lead.company_name} appears to fall under NIS2 directive scope as a "
                    f"<b>{lead.nis2_entity_type or 'covered entity'}</b>. This has implications for "
                    f"cybersecurity requirements, incident reporting, and potential penalties for non-compliance.",
                    ParagraphStyle(
                        "NIS2Alert",
                        parent=self.styles["Body"],
                        backColor=colors.HexColor("#fef3c7"),
                        leftIndent=10,
                        rightIndent=10,
                        spaceBefore=10,
                        spaceAfter=10,
                    ),
                )
            )

        elements.append(Spacer(1, 0.5 * cm))

        # Score breakdown table
        elements.append(Paragraph("Security Dimension Scores", self.styles["Heading2"]))

        dimensions = [
            ("Email Security", lead.email_security),
            ("Technical Hygiene", lead.technical_hygiene),
            ("TLS/SSL Certificate", lead.tls_certificate),
            ("HTTP Security Headers", lead.http_headers),
            ("Cookie Compliance", lead.cookie_compliance),
            ("Attack Surface", lead.attack_surface),
            ("Technology Stack", lead.tech_stack),
            ("Admin Exposure", lead.admin_panel),
        ]

        score_data = [["Dimension", "Score", "Status"]]
        for name, dim in dimensions:
            if dim and dim.analyzed:
                status_color = self._get_score_color(dim.score, dim.max_score)
                status = (
                    "🔴 Critical"
                    if dim.status == "risk"
                    else ("🟡 Needs Work" if dim.status == "warning" else "🟢 Good")
                )
                score_data.append([name, dim.display_score(), status])
            else:
                score_data.append([name, "N/A", "⚪ Not Scanned"])

        score_table = Table(score_data, colWidths=[7 * cm, 3 * cm, 4 * cm])
        score_table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BACKGROUND", (0, 0), (-1, 0), Colors.PRIMARY),
                    ("TEXTCOLOR", (0, 0), (-1, 0), Colors.WHITE),
                    ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                    ("GRID", (0, 0), (-1, -1), 0.5, Colors.TEXT_LIGHT),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [Colors.WHITE, colors.HexColor("#f7fafc")],
                    ),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        elements.append(score_table)

        elements.append(Spacer(1, 1 * cm))

        # Key gaps
        if lead.key_gaps:
            elements.append(Paragraph("Key Security Gaps", self.styles["Heading2"]))
            for gap in lead.key_gaps[:5]:  # Top 5 gaps
                elements.append(Paragraph(f"• {gap}", self.styles["KeyGap"]))

        return elements

    def _build_detailed_findings(self, lead: LeadScore) -> List:
        """Build the detailed findings section."""
        elements = []

        elements.append(Paragraph("Detailed Findings", self.styles["Heading1"]))
        elements.append(
            HRFlowable(
                width="100%", thickness=1, color=Colors.ACCENT, spaceAfter=0.5 * cm
            )
        )

        # Only include dimensions with actual issues (missing controls), using plain-language risk statements.
        dimension_sections = [
            (
                "Email Security",
                lead.email_security,
                "Email security protects against phishing and spoofing. SPF, DKIM, and DMARC help prevent attackers from sending emails that look like they came from your domain.",
                [
                    "Implement DMARC with a policy of 'reject' to prevent email spoofing",
                    "Configure SPF records to authorize legitimate mail servers",
                    "Enable DKIM signing for all outgoing emails",
                    "Monitor DMARC reports to detect unauthorized email sources",
                ],
            ),
            (
                "TLS/SSL Certificate Security",
                lead.tls_certificate,
                "TLS certificates encrypt data in transit and establish trust with visitors. Expired, misconfigured, or weak TLS can expose data and damage reputation.",
                [
                    "Ensure certificates are renewed well before expiration",
                    "Use TLS 1.2 or higher, disable older protocols",
                    "Implement certificate monitoring for unexpected changes",
                ],
            ),
            (
                "HTTP Security Headers",
                lead.http_headers,
                "Security headers help protect visitors against common web attacks (like malicious scripts, clickjacking, and data leakage). They are typically quick wins with a big impact.",
                [
                    "Add a Content-Security-Policy (CSP) to reduce the impact of malicious scripts",
                    "Enable HSTS to enforce HTTPS for all visitors",
                    "Add clickjacking protection (X-Frame-Options or frame-ancestors)",
                    "Set X-Content-Type-Options to prevent content-type confusion attacks",
                ],
            ),
            (
                "Cookie Compliance",
                lead.cookie_compliance,
                "Cookie compliance affects user privacy and regulatory exposure. Setting tracking cookies before consent and missing consent controls can create GDPR risk and reputational impact.",
                [
                    "Implement a cookie consent mechanism compliant with GDPR",
                    "Block non-essential tracking until consent is given",
                    "Document cookies and their purposes in a privacy policy",
                ],
            ),
            (
                "Attack Surface",
                lead.attack_surface,
                "Attack surface is the number of public entry points an attacker can target. Risky or forgotten subdomains and exposed services expand the ways a brand can be compromised.",
                [
                    "Inventory all subdomains and decommission unused ones",
                    "Apply consistent security controls across subdomains",
                    "Monitor for new subdomains and certificates over time",
                ],
            ),
            (
                "Technology Stack",
                lead.tech_stack,
                "Outdated or exposed technology increases the chance of known vulnerabilities being used against the site. This can lead to downtime, defacement, or data exposure.",
                [
                    "Patch outdated components and remove unnecessary services",
                    "Reduce version leakage in HTTP responses where possible",
                    "Set a regular update cadence for public-facing systems",
                ],
            ),
            (
                "Admin Exposure",
                lead.admin_panel,
                "Exposed admin panels are common targets for automated attacks. Without strong protection, they increase the risk of account takeover and service disruption.",
                [
                    "Restrict admin access (IP allowlisting/VPN) where possible",
                    "Enforce MFA for administrative access",
                    "Add brute-force protections (rate limiting/lockout)",
                ],
            ),
        ]

        rendered_any = False
        for title, dim, explanation, recommendations in dimension_sections:
            if not dim or not dim.analyzed or not dim.missing:
                continue
            rendered_any = True
            elements.extend(
                self._build_dimension_section(
                    title=title,
                    dimension=dim,
                    explanation=explanation,
                    recommendations=recommendations,
                )
            )
            elements.append(Spacer(1, 0.5 * cm))

        if not rendered_any:
            elements.append(
                Paragraph(
                    "No major issues were detected in the scanned dimensions. See the Technical Appendix for full scan data.",
                    self.styles["Body"],
                )
            )

        return elements

    def _build_dimension_section(
        self,
        title: str,
        dimension,
        explanation: str,
        recommendations: List[str],
    ) -> List:
        """Build a section for a security dimension."""
        elements = []

        # Section header with score
        if dimension and dimension.analyzed:
            score_text = f"Score: {dimension.display_score()}"
        else:
            score_text = "Not Assessed"

        elements.append(
            Paragraph(f"<b>{title}</b> ({score_text})", self.styles["Heading2"])
        )

        # Explanation
        elements.append(Paragraph(explanation, self.styles["Body"]))

        # Present vs missing (clear and non-technical)
        if dimension and dimension.analyzed and dimension.present:
            elements.append(Paragraph("<b>Already in place:</b>", self.styles["Heading3"]))
            for item in dimension.present[:6]:
                elements.append(Paragraph(f"• {item}", self.styles["Body"]))

        if dimension and dimension.analyzed and dimension.missing:
            elements.append(Paragraph("<b>What needs attention:</b>", self.styles["Heading3"]))
            for item in dimension.missing:
                elements.append(Paragraph(f"• {item}", self.styles["Finding"]))

        if dimension and dimension.analyzed and dimension.risks:
            elements.append(
                Paragraph(f"<b>Risk:</b> {dimension.risks[0]}", self.styles["Body"])
            )

        # Dimension-specific description
        if dimension and dimension.description:
            elements.append(Spacer(1, 0.3 * cm))
            elements.append(
                Paragraph(
                    f"<i>Assessment: {dimension.description}</i>",
                    self.styles["BodySmall"],
                )
            )

        # Recommendations
        elements.append(Paragraph("<b>Recommended next steps:</b>", self.styles["Heading3"]))
        if dimension and dimension.analyzed and dimension.missing:
            for missing_item in dimension.missing[:20]:
                fix = self._next_step_for_missing(dimension, title, missing_item)
                elements.append(
                    Paragraph(
                        f"! {missing_item} → {fix}",
                        self.styles["Recommendation"],
                    )
                )
        else:
            for rec in recommendations[:10]:
                elements.append(Paragraph(f"! {rec}", self.styles["Recommendation"]))

        return elements

    def _generate_next_steps(self, dimension, title: str) -> List[str]:
        """
        Generate remediation steps based on the exact missing findings for a dimension.
        Keeps output practical (engineer-friendly), avoids generic advice.
        """
        if not dimension or not getattr(dimension, "missing", None):
            return []

        missing: List[str] = list(dimension.missing or [])
        steps: List[str] = []

        def add(step: str):
            step = (step or "").strip()
            if step and step not in steps:
                steps.append(step)

        for item in missing:
            add(self._next_step_for_missing(dimension, title, item))

        return steps

    def _next_step_for_missing(self, dimension, title: str, missing_item: str) -> str:
        """Return a single remediation step for a single missing finding."""
        dim_name = (getattr(dimension, "name", "") or title or "").lower()
        item = (missing_item or "").strip()
        msg = item.lower()

        # TLS
        if "tls certificate" in dim_name or "tls" in dim_name or "certificate" in dim_name:
            if "expires" in msg:
                return "Renew the TLS certificate and enable automated renewal/alerts well before expiry."
            if "outdated tls" in msg or "outdated tls protocol" in msg or "protocol" in msg:
                return "Disable legacy TLS versions and enforce TLS 1.2+ (prefer TLS 1.3) on the edge/load balancer."
            if "no valid tls" in msg or "no valid" in msg:
                return "Fix certificate trust issues (correct chain/hostname) so browsers can establish a trusted HTTPS connection."
            return f"Address TLS issue: {item}"

        # HTTP Headers
        if "http headers" in dim_name or "headers" in dim_name:
            if "content-security-policy" in msg:
                return "Implement a Content-Security-Policy (CSP) starting in report-only mode, then tighten to an enforcing policy."
            if "strict-transport-security" in msg or "hsts" in msg:
                return "Enable HSTS with an appropriate max-age, includeSubDomains where safe, and consider preload after validation."
            if "x-frame-options" in msg or "frame-ancestors" in msg:
                return "Prevent clickjacking by setting X-Frame-Options or CSP frame-ancestors to the intended embedding origins."
            if "x-content-type-options" in msg:
                return "Set X-Content-Type-Options: nosniff to prevent content-type confusion in browsers."
            if "referrer-policy" in msg:
                return "Set Referrer-Policy to limit referrer leakage (e.g. strict-origin-when-cross-origin)."
            if "permissions-policy" in msg:
                return "Add a Permissions-Policy to explicitly disable unnecessary browser features."
            return f"Add/adjust missing security header: {item}"

        # Cookies/GDPR
        if "cookie" in dim_name:
            if "consent banner" in msg or "consent flow" in msg:
                return "Implement a clear consent banner with granular choices (analytics/marketing) and store consent decisions."
            if "tracking cookie" in msg or "tracking cookies" in msg:
                return "Block analytics/marketing tags until consent is given (use your CMP to control tag firing)."
            return f"Fix cookie compliance issue: {item}"

        # Attack surface
        if "attack surface" in dim_name or "subdomain" in dim_name:
            if "risky subdomain exposed" in msg or "risky subdomain" in msg:
                return "Restrict or retire the exposed subdomain (remove DNS if unused, require auth/VPN, and block indexing)."
            return f"Reduce attack surface issue: {item}"

        # Tech stack
        if "tech stack" in dim_name or "technology stack" in dim_name:
            if "outdated component" in msg or "outdated software" in msg or "outdated" in msg:
                return "Patch or upgrade the identified component(s) to a supported version and verify against known CVEs."
            if "versions are exposed" in msg or "version leakage" in msg or "exposed via headers" in msg:
                return "Reduce version leakage by adjusting server/app headers (e.g. Server/X-Powered-By) where feasible."
            return f"Remediate tech stack hygiene issue: {item}"

        # Admin exposure
        if "admin exposure" in dim_name or "admin" in dim_name or "login" in dim_name:
            return "Restrict administrative endpoints (IP allowlist/VPN), enforce MFA, and add brute-force protections (rate limiting/lockout)."

        # Email security
        if "email security" in dim_name or "dmarc" in msg or "spf" in msg or "dkim" in msg:
            if "dmarc" in msg:
                return "Deploy DMARC with enforcement (quarantine/reject) and monitor DMARC aggregate reports."
            if "spf" in msg:
                return "Tighten SPF to only include legitimate sending services and end with a strict -all policy where possible."
            if "dkim" in msg:
                return "Enable DKIM signing for outbound mail and rotate keys periodically."
            return f"Improve email authentication: {item}"

        return f"Address: {item}"

    def _build_recommendations(self, lead: LeadScore) -> List:
        """Build the recommendations section."""
        elements = []

        elements.append(Spacer(1, 1 * cm))
        elements.append(Paragraph("Recommendations Summary", self.styles["Heading1"]))
        elements.append(
            HRFlowable(
                width="100%", thickness=1, color=Colors.ACCENT, spaceAfter=0.5 * cm
            )
        )

        elements.append(
            Paragraph(
                "The recommendations below are derived from the exact missing controls detected during the scans.",
                self.styles["Body"],
            )
        )

        remediation_rows = [["Dimension", "Missing finding", "How to fix"]]
        dimensions = [
            ("Email Security", lead.email_security),
            ("Technical Hygiene", lead.technical_hygiene),
            ("TLS/SSL Certificate", lead.tls_certificate),
            ("HTTP Security Headers", lead.http_headers),
            ("Cookie Compliance", lead.cookie_compliance),
            ("Attack Surface", lead.attack_surface),
            ("Technology Stack", lead.tech_stack),
            ("Admin Exposure", lead.admin_panel),
        ]

        for title, dim in dimensions:
            if not dim or not dim.analyzed or not dim.missing:
                continue
            for missing_item in dim.missing:
                fix = self._next_step_for_missing(dim, title, missing_item)
                remediation_rows.append(
                    [
                        Paragraph(title, self.styles["BodySmall"]),
                        Paragraph(str(missing_item), self.styles["BodySmall"]),
                        Paragraph(str(fix), self.styles["BodySmall"]),
                    ]
                )

        if len(remediation_rows) > 1:
            elements.append(Spacer(1, 0.5 * cm))
            elements.append(
                Paragraph("Prioritized Remediation Actions", self.styles["Heading2"])
            )
            table = Table(remediation_rows, colWidths=[4.0 * cm, 6.0 * cm, 6.0 * cm])
            table.setStyle(
                TableStyle(
                    [
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("BACKGROUND", (0, 0), (-1, 0), Colors.PRIMARY),
                        ("TEXTCOLOR", (0, 0), (-1, 0), Colors.WHITE),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("GRID", (0, 0), (-1, -1), 0.5, Colors.TEXT_LIGHT),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [Colors.WHITE, colors.HexColor("#f7fafc")],
                        ),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            elements.append(table)
        else:
            elements.append(Spacer(1, 0.5 * cm))
            elements.append(
                Paragraph(
                    "No missing controls were detected in the analyzed dimensions.",
                    self.styles["Body"],
                )
            )

        # NIS2 specific if applicable
        if lead.nis2_covered:
            elements.append(Spacer(1, 0.5 * cm))
            elements.append(
                Paragraph("NIS2 Compliance Actions", self.styles["Heading2"])
            )

            nis2_recs = [
                "Assess current cybersecurity measures against NIS2 requirements",
                "Establish incident reporting procedures (24h/72h requirements)",
                "Implement supply chain security risk management",
                "Ensure management accountability for cybersecurity",
                "Prepare for potential regulatory audits and supervision",
            ]

            for rec in nis2_recs:
                elements.append(Paragraph(f"• {rec}", self.styles["Body"]))

        return elements

    def _build_technical_appendix(self, lead: LeadScore) -> List:
        """Build the comprehensive technical appendix with all factual scan data (English)."""
        elements = []

        elements.append(Paragraph("Technical Appendix", self.styles["Heading1"]))
        elements.append(
            HRFlowable(
                width="100%", thickness=1, color=Colors.ACCENT, spaceAfter=0.5 * cm
            )
        )

        elements.append(
            Paragraph(
                "This appendix contains the factual technical data from the security assessment. "
                "For engineers, it includes per-scan technical details and raw scan output (when available).",
                self.styles["Body"],
            )
        )

        # Include all scans that produced results (not N/A)
        scan_sections = [
            ("vuln", "Known Vulnerabilities (Shodan)", lead.technical_hygiene, lead.shodan_result, self._appendix_vulnerabilities),
            ("email", "Email Security (DNS)", lead.email_security, lead.dns_result, self._appendix_email),
            ("ssl", "TLS/SSL Certificate", lead.tls_certificate, lead.ssl_result, self._appendix_ssl),
            ("headers", "HTTP Security Headers", lead.http_headers, lead.headers_result, self._appendix_headers),
            ("cookies", "Cookies & Consent", lead.cookie_compliance, lead.cookie_result, self._appendix_cookies),
            ("subdomains", "Attack Surface / Subdomains", lead.attack_surface, lead.subdomain_result, self._appendix_subdomains),
            ("techstack", "Technology Stack", lead.tech_stack, lead.techstack_result, self._appendix_techstack),
            ("admin", "Admin Panels", lead.admin_panel, lead.admin_result, self._appendix_admin),
        ]

        any_added = False
        for _key, title, dim, raw, builder in scan_sections:
            if not raw:
                continue
            any_added = True

            status = getattr(dim, "status", "unknown") if dim else "unknown"
            score_color = (
                Colors.DANGER if status == "risk" else Colors.WARNING if status == "warning" else Colors.SUCCESS if status == "ok" else Colors.TEXT_LIGHT
            )
            score_label = (
                "CRITICAL"
                if status == "risk"
                else "NEEDS ATTENTION"
                if status == "warning"
                else "OK"
                if status == "ok"
                else "UNKNOWN"
            )
            score_text = dim.display_score() if dim and getattr(dim, "analyzed", False) else "N/A"

            elements.append(Spacer(1, 0.5 * cm))
            elements.append(
                Paragraph(
                    f'<font color="{score_color.hexval()}">\u25cf</font> <b>{title}</b>  '
                    f'<font color="{score_color.hexval()}" size="9">({score_label} — {score_text})</font>',
                    self.styles["Heading2"],
                )
            )

            elements.extend(builder(lead))
            elements.extend(self._appendix_raw_json_block(raw))

        if not any_added:
            elements.append(
                Paragraph(
                    "No scan results available to include (all scans N/A or failed).",
                    self.styles["Body"],
                )
            )

        # Methodology (always included)
        elements.append(PageBreak())
        elements.append(Paragraph("Assessment Methodology", self.styles["Heading2"]))
        elements.append(
            Paragraph(
                "This assessment uses passive reconnaissance techniques only. "
                "No active penetration testing or exploitation was performed. Sources used:",
                self.styles["Body"],
            )
        )
        methodology_items = [
            "DNS record queries (SPF, DMARC, DKIM, MX, TXT)",
            "SSL/TLS certificate analysis",
            "HTTP response header inspection",
            "Shodan InternetDB (open ports, CVEs, services)",
            "Certificate Transparency logs (crt.sh) for subdomain discovery",
            "Public website analysis (tech stack, admin panels, governance)",
            "Cookie and consent mechanism inspection",
        ]
        for item in methodology_items:
            elements.append(Paragraph(f"\u2022 {item}", self.styles["BodySmall"]))

        return elements

    def _appendix_raw_json_block(self, raw_obj) -> List:
        """Append a raw JSON dump of a scan result (engineer-friendly)."""
        elements: List = []
        try:
            data = raw_obj.to_dict() if hasattr(raw_obj, "to_dict") else raw_obj
            raw_json = json.dumps(data, indent=2, ensure_ascii=False)
        except Exception as e:
            elements.append(
                Paragraph(f"<i>Raw output not available: {e}</i>", self.styles["BodySmall"])
            )
            return elements

        elements.append(Spacer(1, 0.2 * cm))
        elements.append(Paragraph("<b>Raw scan output (JSON)</b>", self.styles["Heading3"]))
        elements.append(Preformatted(raw_json, self.styles["CodeBlock"]))
        return elements

    # ------------------------------------------------------------------
    # Appendix detail builders per dimension
    # ------------------------------------------------------------------

    def _appendix_vulnerabilities(self, lead: LeadScore) -> List:
        """Known vulnerabilities detail block."""
        elements = []
        shodan = lead.shodan_result

        if not shodan:
            elements.append(
                Paragraph(
                    "<i>Shodan scan not available.</i>", self.styles["BodySmall"]
                )
            )
            return elements

        # Server IP
        elements.append(
            Paragraph(
                f"<b>Server IP:</b> {shodan.ip_address or 'Unknown'}",
                self.styles["Body"],
            )
        )

        # Detected software (CPEs)
        if shodan.cpes:
            elements.append(
                Paragraph("<b>Detected software (CPE):</b>", self.styles["Body"])
            )
            for cpe in shodan.cpes:
                elements.append(Paragraph(f"\u2022 {cpe}", self.styles["BodySmall"]))
        else:
            elements.append(
                Paragraph(
                    "<b>Detected software:</b> No CPE information available",
                    self.styles["Body"],
                )
            )

        # CVEs
        if shodan.vulns:
            elements.append(Spacer(1, 0.3 * cm))
            elements.append(
                Paragraph(
                    f"<b>Total CVEs:</b> {len(shodan.vulns)}",
                    self.styles["Body"],
                )
            )
            cve_data = [["CVE", "Bron"]]
            for cve_id in shodan.vulns[:10]:
                cve_data.append([str(cve_id), "Shodan InternetDB"])
            cve_table = Table(cve_data, colWidths=[5 * cm, 9 * cm])
            cve_table.setStyle(self._detail_table_style(len(cve_data)))
            elements.append(cve_table)
            if len(shodan.vulns) > 10:
                elements.append(
                    Paragraph(
                        f"<i>... and {len(shodan.vulns) - 10} more CVEs (full list available on request)</i>",
                        self.styles["BodySmall"],
                    )
                )
        else:
            elements.append(
                Paragraph(
                    "<b>CVEs:</b> No known vulnerabilities found",
                    self.styles["Body"],
                )
            )

        # Open ports
        if shodan.ports:
            elements.append(Spacer(1, 0.3 * cm))
            port_data = [["Port", "Service", "Risk"]]
            risky_set = set(shodan.risky_ports or [])
            for port in sorted(shodan.ports):
                service = shodan.risky_ports_detail.get(
                    port, self._port_service_name(port)
                )
                if port in risky_set:
                    risk = "HIGH RISK"
                else:
                    risk = "Normal"
                port_data.append([str(port), service, risk])
            port_table = Table(port_data, colWidths=[3 * cm, 7 * cm, 4 * cm])
            style = self._detail_table_style(len(port_data))
            # Color risky rows
            for i, port in enumerate(sorted(shodan.ports), 1):
                if port in risky_set:
                    style.add("TEXTCOLOR", (2, i), (2, i), Colors.DANGER)
                    style.add("FONTNAME", (2, i), (2, i), "Helvetica-Bold")
            port_table.setStyle(style)
            elements.append(Paragraph("<b>Open ports:</b>", self.styles["Body"]))
            elements.append(port_table)
        else:
            elements.append(
                Paragraph(
                    "<b>Open ports:</b> No open ports detected",
                    self.styles["Body"],
                )
            )

        # Risky ports explanation
        if shodan.risky_ports:
            elements.append(Spacer(1, 0.3 * cm))
            elements.append(
                Paragraph(
                    "<b>High-risk ports — details:</b>", self.styles["Body"]
                )
            )
            for port in shodan.risky_ports:
                detail = shodan.risky_ports_detail.get(port, "")
                elements.append(
                    Paragraph(
                        f'\u2022 <font color="{Colors.DANGER.hexval()}"><b>Port {port}</b></font>: {detail}',
                        self.styles["Finding"],
                    )
                )

        return elements

    def _appendix_email(self, lead: LeadScore) -> List:
        """Email security detail block."""
        elements = []
        dns = lead.dns_result

        if not dns:
            elements.append(
                Paragraph("<i>DNS scan not available.</i>", self.styles["BodySmall"])
            )
            return elements

        # SPF
        has_spf = bool(dns.spf_record)
        spf_policy = dns.spf_policy or "missing"
        spf_color = (
            Colors.SUCCESS
            if dns.spf_score == 2
            else (Colors.WARNING if dns.spf_score == 1 else Colors.DANGER)
        )
        elements.append(Paragraph(f"<b>SPF Record:</b>", self.styles["Body"]))
        elements.append(
            Paragraph(
                f"{dns.spf_record or 'Not configured'}", self.styles["BodySmall"]
            )
        )
        spf_assessment = (
            "hard fail (-all) — good"
            if "-all" in (dns.spf_record or "")
            else (
                "soft fail (~all) — weak"
                if "~all" in (dns.spf_record or "")
                else ("missing — no protection" if not has_spf else spf_policy)
            )
        )
        elements.append(
            Paragraph(
                f'<font color="{spf_color.hexval()}">Assessment: {spf_assessment}</font>',
                self.styles["BodySmall"],
            )
        )

        elements.append(Spacer(1, 0.2 * cm))

        # DMARC
        has_dmarc = bool(dns.dmarc_record)
        dmarc_policy = dns.dmarc_policy or "missing"
        dmarc_color = (
            Colors.SUCCESS
            if dns.dmarc_score == 2
            else (Colors.WARNING if dns.dmarc_score == 1 else Colors.DANGER)
        )
        elements.append(Paragraph(f"<b>DMARC Record:</b>", self.styles["Body"]))
        elements.append(
            Paragraph(
                f"{dns.dmarc_record or 'Not configured'}", self.styles["BodySmall"]
            )
        )
        dmarc_assessment = {
            "reject": "reject — good, unauthenticated mail is rejected",
            "quarantine": "quarantine — moderate, unauthenticated mail goes to spam",
            "none (monitoring only)": "none — monitoring only, no enforcement",
            "missing": "missing — no DMARC protection",
        }.get(dmarc_policy, dmarc_policy)
        elements.append(
            Paragraph(
                f'<font color="{dmarc_color.hexval()}">Assessment: {dmarc_assessment}</font>',
                self.styles["BodySmall"],
            )
        )

        elements.append(Spacer(1, 0.2 * cm))

        # DKIM
        dkim_color = Colors.SUCCESS if dns.dkim_found else Colors.DANGER
        elements.append(Paragraph(f"<b>DKIM:</b>", self.styles["Body"]))
        if dns.dkim_found:
            elements.append(
                Paragraph(
                    f'<font color="{dkim_color.hexval()}">Found</font> (selector: {dns.dkim_selector or "unknown"})',
                    self.styles["BodySmall"],
                )
            )
        else:
            elements.append(
                Paragraph(
                    f'<font color="{dkim_color.hexval()}">Not found</font> — checked common selectors: '
                    f"google, selector1, selector2, default, mail, k1, dkim, s1, s2, protonmail, etc.",
                    self.styles["BodySmall"],
                )
            )

        elements.append(Spacer(1, 0.3 * cm))

        # Risk explanation
        if not has_dmarc or dmarc_policy in ("missing", "none (monitoring only)"):
            elements.append(
                Paragraph(
                    f'<font color="{Colors.DANGER.hexval()}"><b>Risk explanation:</b></font> '
                    f"With the current configuration, someone could send an email as ceo@{lead.domain} "
                    f"to any recipient. Many recipients will not be able to tell it apart from a legitimate message.",
                    self.styles["Body"],
                )
            )

        elements.append(
            Paragraph(
                "<b>Verification:</b> You can verify via MXToolbox.com — enter the domain and check the DMARC status.",
                self.styles["BodySmall"],
            )
        )

        return elements

    def _appendix_headers(self, lead: LeadScore) -> List:
        """Security Headers detail block."""
        elements = []
        hdr = lead.headers_result

        if not hdr:
            elements.append(
                Paragraph(
                    "<i>Header scan not available.</i>", self.styles["BodySmall"]
                )
            )
            return elements

        elements.append(Paragraph(f"<b>Grade:</b> {hdr.grade}", self.styles["Body"]))

        hp = hdr.headers_present or {}

        # Present headers
        present_list = [h for h in hp.keys()]
        if present_list:
            elements.append(Paragraph("<b>Present headers:</b>", self.styles["Body"]))
            for h in present_list:
                elements.append(
                    Paragraph(
                        f'\u2022 <font color="{Colors.SUCCESS.hexval()}">{h}</font>: {str(hp[h])[:80]}',
                        self.styles["BodySmall"],
                    )
                )

        # Missing headers with risk explanation
        header_risks = {
            "Strict-Transport-Security": "Traffic can be downgraded or intercepted on hostile networks",
            "Content-Security-Policy": "Malicious scripts can be injected more easily (XSS/injection impact)",
            "X-Frame-Options": "Site can be embedded in an invisible frame (clickjacking)",
            "X-Content-Type-Options": "Browser may interpret files as executable content in edge cases",
            "Referrer-Policy": "Internal URLs and identifiers can leak to external parties",
            "Permissions-Policy": "Injected code may be able to request sensitive browser features",
        }
        missing = hdr.headers_missing or []
        # Also check standard headers not in headers_present
        for std_header in header_risks:
            if std_header not in hp and std_header not in missing:
                missing.append(std_header)

        if missing:
            elements.append(Spacer(1, 0.3 * cm))
            miss_data = [["Header", "Status", "Risk"]]
            for h in missing:
                risk = header_risks.get(h, "Security risk")
                miss_data.append([h, "Missing", risk])
            miss_table = Table(miss_data, colWidths=[5 * cm, 2.5 * cm, 9 * cm])
            style = self._detail_table_style(len(miss_data))
            # Color the Status column red
            for i in range(1, len(miss_data)):
                style.add("TEXTCOLOR", (1, i), (1, i), Colors.DANGER)
                style.add("FONTNAME", (1, i), (1, i), "Helvetica-Bold")
            miss_table.setStyle(style)
            elements.append(
                Paragraph("<b>Missing headers:</b>", self.styles["Body"])
            )
            elements.append(miss_table)

        # Info leakage
        if hdr.info_leakage:
            elements.append(Spacer(1, 0.3 * cm))
            elements.append(
                Paragraph("<b>Information leakage via headers:</b>", self.styles["Body"])
            )
            for header_name, value in hdr.info_leakage.items():
                elements.append(
                    Paragraph(
                        f'\u2022 <font color="{Colors.WARNING.hexval()}">{header_name}</font>: {value}',
                        self.styles["BodySmall"],
                    )
                )

        return elements

    def _appendix_subdomains(self, lead: LeadScore) -> List:
        """Attack surface / subdomains detail block."""
        elements = []
        sub = lead.subdomain_result

        if not sub:
            elements.append(
                Paragraph(
                    "<i>Subdomain scan not available.</i>", self.styles["BodySmall"]
                )
            )
            return elements

        total = sub.total_count or len(sub.subdomains_found or [])
        elements.append(
            Paragraph(
                f"<b>Total subdomains found:</b> {total}", self.styles["Body"]
            )
        )

        # Risky subdomains table
        if sub.risky_subdomains:
            risky_data = [["Subdomain", "Type", "Risk"]]
            for risky in sub.risky_subdomains:
                if isinstance(risky, dict):
                    name = risky.get("subdomain", risky.get("name", str(risky)))
                    rtype = risky.get("type", risky.get("category", ""))
                    risk = risky.get("risk", risky.get("description", ""))
                else:
                    name = str(risky)
                    rtype = ""
                    risk = ""
                risky_data.append([name, rtype, risk])

            risky_table = Table(risky_data, colWidths=[5.5 * cm, 3 * cm, 7.5 * cm])
            style = self._detail_table_style(len(risky_data))
            risky_table.setStyle(style)
            elements.append(Spacer(1, 0.3 * cm))
            elements.append(
                Paragraph("<b>Risky subdomains:</b>", self.styles["Body"])
            )
            elements.append(risky_table)

        # Neutral subdomains summary
        neutral_count = len(sub.neutral_subdomains or [])
        if neutral_count > 0:
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(
                Paragraph(
                    f"<b>Non-risky subdomains:</b> {neutral_count} regular subdomains "
                    f"(www, mail, cdn, etc.)",
                    self.styles["Body"],
                )
            )

        return elements

    def _appendix_ssl(self, lead: LeadScore) -> List:
        """TLS/SSL certificate detail block."""
        elements = []
        ssl = lead.ssl_result

        if not ssl:
            elements.append(
                Paragraph("<i>SSL scan not available.</i>", self.styles["BodySmall"])
            )
            return elements

        # Certificate info table
        valid_text = "Yes" if ssl.certificate_valid else "No"
        valid_color = Colors.SUCCESS if ssl.certificate_valid else Colors.DANGER

        not_before_str = str(ssl.not_before) if ssl.not_before else "Unknown"
        not_after_str = str(ssl.not_after) if ssl.not_after else "Unknown"

        days_text = (
            str(ssl.days_until_expiry) if ssl.days_until_expiry is not None else "N/A"
        )
        if ssl.days_until_expiry is not None and ssl.days_until_expiry < 90:
            days_text += "  ⚠️ WARNING: less than 90 days"

        protocol = ssl.protocol_version or "Unknown"

        ssl_data = [
            ["Property", "Value"],
            ["Certificate valid", valid_text],
            ["Issuer", ssl.issuer or "Unknown"],
            ["Valid from", not_before_str],
            ["Valid until", not_after_str],
            ["Days until expiry", days_text],
            ["Protocol", protocol],
        ]

        if ssl.san_domains:
            ssl_data.append(
                [
                    "SAN Domains",
                    ", ".join(ssl.san_domains[:10])
                    + (
                        f" (+{len(ssl.san_domains)-10} more)"
                        if len(ssl.san_domains) > 10
                        else ""
                    ),
                ]
            )

        ssl_table = Table(ssl_data, colWidths=[5 * cm, 9 * cm])
        style = self._detail_table_style(len(ssl_data))
        # Color the valid row
        if not ssl.certificate_valid:
            style.add("TEXTCOLOR", (1, 1), (1, 1), Colors.DANGER)
            style.add("FONTNAME", (1, 1), (1, 1), "Helvetica-Bold")
        ssl_table.setStyle(style)
        elements.append(ssl_table)

        # Weak points
        weak_points = []
        if protocol and ("1.0" in protocol or "1.1" in protocol):
            weak_points.append(
                f"Outdated protocol ({protocol}) — TLS 1.0/1.1 is insecure and deprecated"
            )
        if ssl.issuer and "self" in (ssl.issuer or "").lower():
            weak_points.append("Self-signed certificate — not trusted by browsers")
        if ssl.days_until_expiry is not None and ssl.days_until_expiry <= 0:
            weak_points.append("Certificate is EXPIRED")
        elif ssl.days_until_expiry is not None and ssl.days_until_expiry < 30:
            weak_points.append(
                f"Certificate expires within {ssl.days_until_expiry} days"
            )

        if weak_points:
            elements.append(Spacer(1, 0.3 * cm))
            elements.append(Paragraph("<b>Weak points:</b>", self.styles["Body"]))
            for wp in weak_points:
                elements.append(
                    Paragraph(
                        f'\u2022 <font color="{Colors.DANGER.hexval()}">{wp}</font>',
                        self.styles["Finding"],
                    )
                )

        return elements

    def _appendix_admin(self, lead: LeadScore) -> List:
        """Admin Panels detail block."""
        elements = []
        admin = lead.admin_result

        if not admin:
            elements.append(
                Paragraph(
                    "<i>Admin scan not available.</i>", self.styles["BodySmall"]
                )
            )
            return elements

        # Found admin/login pages
        all_pages = (admin.admin_pages_found or []) + (admin.login_pages_found or [])
        if all_pages:
            admin_data = [["URL", "Type", "MFA detection", "Risk"]]
            for page in all_pages:
                if isinstance(page, dict):
                    url = page.get("url", page.get("path", str(page)))
                    ptype = page.get("type", page.get("category", "Admin"))
                    mfa = page.get("mfa", "Not detected")
                    risk = page.get("risk", "Brute-force, credential stuffing")
                else:
                    url = str(page)
                    ptype = "Admin/Login"
                    mfa = "Not detected"
                    risk = "Brute-force, credential stuffing"
                admin_data.append(
                    [Paragraph(str(url), self.styles["BodySmall"]), ptype, mfa, risk]
                )
            admin_table = Table(
                admin_data, colWidths=[5.5 * cm, 3 * cm, 3.5 * cm, 4 * cm]
            )
            admin_table.setStyle(self._detail_table_style(len(admin_data)))
            elements.append(
                Paragraph("<b>Admin/login pages found:</b>", self.styles["Body"])
            )
            elements.append(admin_table)

            # MFA / SSO info
            if admin.mfa_indicators:
                elements.append(Spacer(1, 0.2 * cm))
                elements.append(
                    Paragraph(
                        "<b>MFA indicators:</b> " + ", ".join(admin.mfa_indicators),
                        self.styles["Body"],
                    )
                )
            if admin.sso_providers_detected:
                elements.append(
                    Paragraph(
                        "<b>SSO providers:</b> "
                        + ", ".join(admin.sso_providers_detected),
                        self.styles["Body"],
                    )
                )
        else:
            elements.append(
                Paragraph(
                    "<b>Admin pages found:</b> No publicly accessible admin/login pages found.",
                    self.styles["Body"],
                )
            )

        # Paths checked
        if admin.pages_checked:
            elements.append(Spacer(1, 0.3 * cm))
            elements.append(
                Paragraph(
                    f"<b>Paths checked ({len(admin.pages_checked)}):</b> "
                    f"{', '.join(admin.pages_checked[:20])}"
                    f"{'...' if len(admin.pages_checked) > 20 else ''}",
                    self.styles["BodySmall"],
                )
            )

        return elements

    def _appendix_governance(self, lead: LeadScore) -> List:
        """Security Governance detail block."""
        elements = []
        gov = lead.governance_result

        if not gov:
            elements.append(
                Paragraph(
                    "<i>Governance scan not available.</i>", self.styles["BodySmall"]
                )
            )
            return elements

        # CISO / Security Officer
        ciso_color = Colors.SUCCESS if gov.has_visible_ciso else Colors.DANGER
        ciso_text = "Yes" if gov.has_visible_ciso else "No"
        elements.append(
            Paragraph(
                f'<b>CISO/Security Officer visible:</b> <font color="{ciso_color.hexval()}">{ciso_text}</font>',
                self.styles["Body"],
            )
        )

        if gov.security_leaders_found:
            elements.append(
                Paragraph(
                    "<b>Security roles found:</b> "
                    + ", ".join(gov.security_leaders_found),
                    self.styles["BodySmall"],
                )
            )
        if gov.security_titles_found:
            elements.append(
                Paragraph(
                    "<b>Titles found:</b> " + ", ".join(gov.security_titles_found),
                    self.styles["BodySmall"],
                )
            )

        # Where searched
        if gov.pages_checked:
            elements.append(
                Paragraph(
                    "<b>Where checked:</b> " + ", ".join(gov.pages_checked[:10]),
                    self.styles["BodySmall"],
                )
            )

        elements.append(Spacer(1, 0.2 * cm))

        # Annual report
        if gov.annual_report_found:
            elements.append(
                Paragraph(
                    f"<b>Annual report found:</b> Yes"
                    f"{' — ' + gov.annual_report_url if gov.annual_report_url else ''}"
                    f"{' (' + gov.annual_report_year + ')' if gov.annual_report_year else ''}",
                    self.styles["Body"],
                )
            )
            elements.append(
                Paragraph(
                    f"<b>Mentions of cyber/security/risk in the report:</b> {gov.cyber_mentions_in_report}",
                    self.styles["BodySmall"],
                )
            )
        else:
            elements.append(
                Paragraph("<b>Annual report found:</b> No", self.styles["Body"])
            )

        # NIS2 implication
        elements.append(Spacer(1, 0.3 * cm))
        elements.append(
            Paragraph(
                f'<font color="{Colors.WARNING.hexval()}"><b>NIS2 implication:</b></font> '
                f"NIS2 expects management accountability. Without visible security governance, "
                f"it is unclear who owns cybersecurity policy and incident response readiness.",
                self.styles["Body"],
            )
        )

        return elements

    def _appendix_techstack(self, lead: LeadScore) -> List:
        """Tech Stack detail block."""
        elements = []
        ts = lead.techstack_result

        if not ts:
            elements.append(
                Paragraph(
                    "<i>Tech stack scan not available.</i>", self.styles["BodySmall"]
                )
            )
            return elements

        # Detected technologies table
        all_tech = (ts.technologies or []) + (ts.outdated_software or [])
        if all_tech:
            tech_data = [["Software", "Version", "Status", "Risk"]]
            seen = set()
            for tech in all_tech:
                if isinstance(tech, dict):
                    name = tech.get("name", tech.get("software", str(tech)))
                    version = tech.get("version", tech.get("detected_version", ""))
                    status = tech.get("status", "")
                    status_l = str(status).lower()
                    if status_l in ("verouderd", "outdated"):
                        status = "Outdated"
                    elif status_l in ("actueel", "current"):
                        status = "Current"
                    risk = tech.get("risk", tech.get("description", ""))
                    # Mark outdated
                    if not status and tech in (ts.outdated_software or []):
                        status = "Outdated"
                        risk = risk or "Known vulnerabilities possible"
                else:
                    name = str(tech)
                    version = ""
                    status = ""
                    risk = ""
                key = f"{name}:{version}"
                if key not in seen:
                    seen.add(key)
                    tech_data.append(
                        [name, version or "—", status or "Current", risk or "—"]
                    )

            if len(tech_data) > 1:
                tech_table = Table(
                    tech_data, colWidths=[4 * cm, 3 * cm, 3 * cm, 4 * cm]
                )
                style = self._detail_table_style(len(tech_data))
                # Color outdated rows
                for i, tech in enumerate(all_tech, 1):
                    if i < len(tech_data) and isinstance(tech, dict):
                        if (
                            tech in (ts.outdated_software or [])
                            or "verouderd" in str(tech.get("status", "")).lower()
                            or "outdated" in str(tech.get("status", "")).lower()
                            or "end-of-life" in str(tech.get("status", "")).lower()
                        ):
                            style.add("TEXTCOLOR", (2, i), (2, i), Colors.DANGER)
                            style.add("FONTNAME", (2, i), (2, i), "Helvetica-Bold")
                tech_table.setStyle(style)
                elements.append(
                    Paragraph("<b>Detected software:</b>", self.styles["Body"])
                )
                elements.append(tech_table)

        # Version leaks
        if ts.version_leaks:
            elements.append(Spacer(1, 0.3 * cm))
            elements.append(
                Paragraph(
                    "<b>Server headers leaking version information:</b>",
                    self.styles["Body"],
                )
            )
            for leak in ts.version_leaks:
                if isinstance(leak, dict):
                    header = leak.get("header", leak.get("name", ""))
                    value = leak.get("value", leak.get("version", ""))
                    elements.append(
                        Paragraph(
                            f'\u2022 <font color="{Colors.WARNING.hexval()}">{header}</font>: {value}',
                            self.styles["BodySmall"],
                        )
                    )
                else:
                    elements.append(
                        Paragraph(f"\u2022 {leak}", self.styles["BodySmall"])
                    )

        # Server info
        if ts.server_info:
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(
                Paragraph(
                    f'<b>Server header:</b> <font color="{Colors.WARNING.hexval()}">{ts.server_info}</font>',
                    self.styles["Body"],
                )
            )

        # CMS
        if ts.cms_detected:
            elements.append(
                Paragraph(
                    f"<b>CMS detected:</b> {ts.cms_detected}", self.styles["Body"]
                )
            )

        return elements

    def _appendix_cookies(self, lead: LeadScore) -> List:
        """Cookies & consent detail block."""
        elements = []
        c = lead.cookie_result

        if not c:
            elements.append(
                Paragraph("<i>Cookie scan not available.</i>", self.styles["BodySmall"])
            )
            return elements

        elements.append(
            Paragraph(
                f"<b>Consent banner:</b> {'Yes' if c.consent_banner_detected else 'No'}"
                + (f" ({c.consent_provider})" if c.consent_provider else ""),
                self.styles["Body"],
            )
        )
        elements.append(
            Paragraph(f"<b>Compliance status:</b> {c.compliance_status}", self.styles["Body"])
        )
        elements.append(
            Paragraph(f"<b>Tracking cookies:</b> {len(c.tracking_cookies or [])}", self.styles["Body"])
        )
        if c.tracking_cookies:
            for name in c.tracking_cookies[:25]:
                elements.append(Paragraph(f"• {name}", self.styles["BodySmall"]))
            if len(c.tracking_cookies) > 25:
                elements.append(
                    Paragraph(f"• ...and {len(c.tracking_cookies) - 25} more", self.styles["BodySmall"])
                )

        if c.cookies_before_consent:
            elements.append(Spacer(1, 0.3 * cm))
            elements.append(Paragraph("<b>Cookies set before consent:</b>", self.styles["Body"]))
            cookie_data = [["Name", "Domain", "Path", "Attributes"]]
            for ck in c.cookies_before_consent[:50]:
                if isinstance(ck, dict):
                    attrs = []
                    for k in ("secure", "httponly", "samesite", "expires"):
                        if k in ck and ck.get(k) not in (None, "", False):
                            attrs.append(f"{k}={ck.get(k)}")
                    cookie_data.append(
                        [
                            ck.get("name", "—"),
                            ck.get("domain", "—"),
                            ck.get("path", "—"),
                            ", ".join(attrs) or "—",
                        ]
                    )
            tbl = Table(cookie_data, colWidths=[4 * cm, 4 * cm, 2.5 * cm, 4.5 * cm])
            tbl.setStyle(self._detail_table_style(len(cookie_data)))
            elements.append(tbl)

        if c.findings:
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(Paragraph("<b>Scanner findings:</b>", self.styles["Body"]))
            for f in c.findings[:30]:
                elements.append(Paragraph(f"• {f}", self.styles["BodySmall"]))

        if c.error:
            elements.append(
                Paragraph(f"<b>Error:</b> {c.error}", self.styles["BodySmall"])
            )

        return elements

    def _appendix_jobs(self, lead: LeadScore) -> List:
        """Jobs / hiring signals detail block."""
        elements = []
        j = lead.jobs_result

        if not j:
            elements.append(
                Paragraph("<i>Jobs scan not available.</i>", self.styles["BodySmall"])
            )
            return elements

        elements.append(
            Paragraph(
                f"<b>Jobs page found:</b> {'Yes' if j.jobs_page_found else 'No'}",
                self.styles["Body"],
            )
        )
        if j.jobs_page_url:
            elements.append(Paragraph(f"<b>Jobs page URL:</b> {j.jobs_page_url}", self.styles["BodySmall"]))
        elements.append(Paragraph(f"<b>Total jobs found:</b> {j.total_jobs_found}", self.styles["Body"]))
        elements.append(Paragraph(f"<b>Security jobs found:</b> {j.security_jobs_found}", self.styles["Body"]))

        if j.security_job_titles:
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(Paragraph("<b>Security job titles:</b>", self.styles["Body"]))
            for t in j.security_job_titles[:25]:
                elements.append(Paragraph(f"• {t}", self.styles["BodySmall"]))

        if j.security_keywords_found:
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(Paragraph("<b>Security keywords found:</b>", self.styles["Body"]))
            elements.append(Paragraph(", ".join(j.security_keywords_found[:50]), self.styles["BodySmall"]))

        if j.pages_checked:
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(Paragraph("<b>Pages checked:</b>", self.styles["Body"]))
            for u in j.pages_checked[:20]:
                elements.append(Paragraph(f"• {u}", self.styles["BodySmall"]))
            if len(j.pages_checked) > 20:
                elements.append(Paragraph(f"• ...and {len(j.pages_checked) - 20} more", self.styles["BodySmall"]))

        if j.findings:
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(Paragraph("<b>Scanner findings:</b>", self.styles["Body"]))
            for f in j.findings[:30]:
                elements.append(Paragraph(f"• {f}", self.styles["BodySmall"]))

        if j.error:
            elements.append(Paragraph(f"<b>Error:</b> {j.error}", self.styles["BodySmall"]))

        return elements

    def _appendix_website(self, lead: LeadScore) -> List:
        """Website content signals detail block."""
        elements = []
        w = lead.website_result

        if not w:
            elements.append(
                Paragraph("<i>Website scan not available.</i>", self.styles["BodySmall"])
            )
            return elements

        elements.append(Paragraph(f"<b>Pages checked:</b> {len(w.pages_checked or [])}", self.styles["Body"]))
        if w.pages_found:
            elements.append(Paragraph("<b>Pages found:</b>", self.styles["Body"]))
            for p in w.pages_found[:25]:
                elements.append(Paragraph(f"• {p}", self.styles["BodySmall"]))

        elements.append(Paragraph(f"<b>Security page:</b> {'Yes' if w.has_security_page else 'No'}", self.styles["Body"]))
        elements.append(Paragraph(f"<b>Privacy page:</b> {'Yes' if w.has_privacy_page else 'No'}", self.styles["Body"]))
        elements.append(Paragraph(f"<b>Security communication score:</b> {w.security_communication_score}", self.styles["Body"]))
        elements.append(Paragraph(f"<b>NIS2 readiness score:</b> {w.nis2_readiness_score}", self.styles["Body"]))

        if w.security_keywords_found:
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(Paragraph("<b>Security keywords found:</b>", self.styles["Body"]))
            elements.append(Paragraph(", ".join(w.security_keywords_found[:80]), self.styles["BodySmall"]))

        if w.nis2_keywords_found:
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(Paragraph("<b>NIS2 keywords found:</b>", self.styles["Body"]))
            elements.append(Paragraph(", ".join(w.nis2_keywords_found[:80]), self.styles["BodySmall"]))

        if w.sector_indicators:
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(Paragraph("<b>Sector indicators:</b>", self.styles["Body"]))
            for k, vals in list(w.sector_indicators.items())[:20]:
                elements.append(Paragraph(f"• {k}: {', '.join(vals[:20])}", self.styles["BodySmall"]))

        if w.findings:
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(Paragraph("<b>Scanner findings:</b>", self.styles["Body"]))
            for f in w.findings[:30]:
                elements.append(Paragraph(f"• {f}", self.styles["BodySmall"]))

        if w.error:
            elements.append(Paragraph(f"<b>Error:</b> {w.error}", self.styles["BodySmall"]))

        return elements

    # ------------------------------------------------------------------
    # Shared helpers for appendix
    # ------------------------------------------------------------------

    def _detail_table_style(self, row_count: int) -> TableStyle:
        """Return a reusable table style for appendix detail tables."""
        return TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BACKGROUND", (0, 0), (-1, 0), Colors.SECONDARY),
                ("TEXTCOLOR", (0, 0), (-1, 0), Colors.WHITE),
                ("GRID", (0, 0), (-1, -1), 0.5, Colors.TEXT_LIGHT),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [Colors.WHITE, colors.HexColor("#f7fafc")],
                ),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )

    @staticmethod
    def _port_service_name(port: int) -> str:
        """Map common ports to service names."""
        common = {
            80: "HTTP",
            443: "HTTPS",
            22: "SSH",
            21: "FTP",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            110: "POP3",
            143: "IMAP",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            5432: "PostgreSQL",
            3389: "RDP",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            445: "SMB",
            135: "MSRPC",
            139: "NetBIOS",
            1433: "MSSQL",
            1521: "Oracle",
            5900: "VNC",
            6379: "Redis",
            27017: "MongoDB",
        }
        return common.get(port, f"Port {port}")

    # Helper methods for extracting findings
    def _get_email_findings(self, lead: LeadScore) -> List[str]:
        """Extract email security findings."""
        findings = []
        if lead.dns_result:
            if not lead.dns_result.spf_record:
                findings.append(
                    "No SPF record configured - vulnerable to email spoofing"
                )
            elif lead.dns_result.spf_record and "~all" in lead.dns_result.spf_record:
                findings.append("SPF uses soft fail (~all) instead of hard fail (-all)")

            if not lead.dns_result.dmarc_record:
                findings.append(
                    "No DMARC policy configured - no email authentication enforcement"
                )
            elif (
                lead.dns_result.dmarc_record
                and "p=none" in lead.dns_result.dmarc_record
            ):
                findings.append(
                    "DMARC policy is 'none' - monitoring only, no enforcement"
                )

            if not lead.dns_result.dkim_found:
                findings.append("DKIM not detected - email integrity not verified")
        else:
            findings.append("DNS scan not completed - email security status unknown")

        return findings

    def _get_ssl_findings(self, lead: LeadScore) -> List[str]:
        """Extract SSL/TLS findings."""
        findings = []
        if lead.ssl_result:
            if not lead.ssl_result.certificate_valid:
                findings.append("SSL certificate is invalid or not trusted")

            if lead.ssl_result.days_until_expiry is not None:
                if lead.ssl_result.days_until_expiry <= 0:
                    findings.append("SSL certificate has EXPIRED")
                elif lead.ssl_result.days_until_expiry <= 30:
                    findings.append(
                        f"SSL certificate expires in {lead.ssl_result.days_until_expiry} days"
                    )

            if (
                lead.ssl_result.protocol_version
                and "TLS 1.0" in lead.ssl_result.protocol_version
            ):
                findings.append("Deprecated TLS 1.0 protocol in use")
            elif (
                lead.ssl_result.protocol_version
                and "TLS 1.1" in lead.ssl_result.protocol_version
            ):
                findings.append("Deprecated TLS 1.1 protocol in use")
        else:
            findings.append("SSL scan not completed - certificate status unknown")

        return findings

    def _get_headers_findings(self, lead: LeadScore) -> List[str]:
        """Extract HTTP header findings."""
        findings = []
        if lead.headers_result:
            hp = lead.headers_result.headers_present or {}
            if "Content-Security-Policy" not in hp:
                findings.append("Missing Content-Security-Policy header")
            if "Strict-Transport-Security" not in hp:
                findings.append("Missing Strict-Transport-Security (HSTS) header")
            if "X-Frame-Options" not in hp:
                findings.append("Missing X-Frame-Options header - clickjacking risk")
            if "X-Content-Type-Options" not in hp:
                findings.append("Missing X-Content-Type-Options header")
            if "Referrer-Policy" not in hp:
                findings.append("Missing Referrer-Policy header")
        else:
            findings.append("Headers scan not completed - security headers unknown")

        return findings

    def _get_cookie_findings(self, lead: LeadScore) -> List[str]:
        """Extract cookie findings."""
        findings = []
        if lead.cookie_result:
            if not lead.cookie_result.consent_banner_detected:
                findings.append(
                    "No cookie consent mechanism detected - potential GDPR issue"
                )
            if lead.cookie_result.tracking_cookies:
                findings.append(
                    f"{len(lead.cookie_result.tracking_cookies)} tracking cookies detected"
                )
            if lead.cookie_result.cookies_before_consent:
                findings.append(
                    f"{len(lead.cookie_result.cookies_before_consent)} cookies set before consent"
                )
        else:
            findings.append("Cookie scan not completed")

        return findings

    def _get_subdomain_findings(self, lead: LeadScore) -> List[str]:
        """Extract subdomain/attack surface findings."""
        findings = []
        if lead.subdomain_result:
            count = (
                len(lead.subdomain_result.subdomains_found)
                if lead.subdomain_result.subdomains_found
                else 0
            )
            findings.append(
                f"Discovered {count} subdomains via certificate transparency"
            )

            if lead.subdomain_result.risky_subdomains:
                findings.append(
                    f"Found {len(lead.subdomain_result.risky_subdomains)} potentially risky subdomains"
                )
                for risky in lead.subdomain_result.risky_subdomains[:3]:
                    # risky_subdomains is a list of dicts
                    if isinstance(risky, dict):
                        findings.append(f"  - {risky.get('subdomain', risky)}")
                    else:
                        findings.append(f"  - {risky}")
        else:
            findings.append("Subdomain scan not completed")

        return findings

    def _get_tier_color(self, tier: LeadTier):
        """Get color for tier."""
        if tier == LeadTier.HOT:
            return Colors.DANGER
        elif tier == LeadTier.WARM:
            return Colors.WARNING
        return Colors.SUCCESS

    def _get_tier_description(self, tier: LeadTier) -> str:
        """Get description for tier."""
        if tier == LeadTier.HOT:
            return "HIGH RISK - Significant security gaps requiring immediate attention"
        elif tier == LeadTier.WARM:
            return "MODERATE RISK - Notable gaps that should be addressed"
        return "LOW RISK - Generally well prepared with minor improvements possible"

    def _get_score_color(self, score: Optional[float], max_score: Optional[float] = None):
        """Get color for an individual dimension using percentage thresholds."""
        if score is None:
            return Colors.TEXT_LIGHT
        if not max_score:
            max_score = 2.0

        try:
            pct = float(score) / float(max_score)
        except Exception:
            return Colors.TEXT_LIGHT

        if pct <= 0.33:
            return Colors.DANGER
        if pct <= 0.66:
            return Colors.WARNING
        return Colors.SUCCESS


def generate_company_pdf(lead: LeadScore, output_dir: str = "output/pdfs") -> str:
    """
    Convenience function to generate a PDF report for a single company.

    Args:
        lead: LeadScore object
        output_dir: Directory for output PDFs

    Returns:
        Path to generated PDF
    """
    generator = PDFReportGenerator()

    # Create safe filename from company name
    safe_name = "".join(
        c for c in lead.company_name if c.isalnum() or c in (" ", "-", "_")
    ).strip()
    safe_name = safe_name.replace(" ", "_")

    output_path = (
        Path(output_dir)
        / f"security_report_{safe_name}_{datetime.now().strftime('%Y%m%d')}.pdf"
    )

    return generator.generate(lead, str(output_path))
