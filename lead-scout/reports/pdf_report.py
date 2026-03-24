"""
PDF Report Generator - Professional Security Assessment Reports
Generates individual company PDF reports with professional business styling.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path
import io
import os

# ReportLab imports
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm, cm, inch
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, HRFlowable, ListFlowable, ListItem,
        KeepTogether, Flowable
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
    PRIMARY = colors.HexColor('#1a365d')      # Deep blue
    SECONDARY = colors.HexColor('#2d3748')    # Dark slate
    ACCENT = colors.HexColor('#3182ce')       # Bright blue
    SUCCESS = colors.HexColor('#38a169')      # Green
    WARNING = colors.HexColor('#e67e22')      # Orange
    DANGER = colors.HexColor('#e53e3e')       # Red
    TEXT = colors.HexColor('#2d3748')         # Dark gray text
    TEXT_LIGHT = colors.HexColor('#718096')   # Light gray text
    BACKGROUND = colors.HexColor('#f7fafc')   # Light background
    WHITE = colors.white
    BLACK = colors.black


class ScoreGauge(Flowable):
    """Custom flowable for score visualization."""
    
    def __init__(self, score: float, max_score: float = 18.0, width: float = 150, height: float = 80):
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
        self.canv.setFillColor(colors.HexColor('#e2e8f0'))
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
            'Title': ParagraphStyle(
                'CustomTitle',
                parent=base_styles['Title'],
                fontSize=28,
                textColor=Colors.PRIMARY,
                spaceAfter=20,
                alignment=TA_LEFT,
                fontName='Helvetica-Bold'
            ),
            'Subtitle': ParagraphStyle(
                'CustomSubtitle',
                parent=base_styles['Heading2'],
                fontSize=14,
                textColor=Colors.TEXT_LIGHT,
                spaceAfter=30,
                alignment=TA_LEFT
            ),
            'Heading1': ParagraphStyle(
                'CustomH1',
                parent=base_styles['Heading1'],
                fontSize=18,
                textColor=Colors.PRIMARY,
                spaceBefore=20,
                spaceAfter=12,
                fontName='Helvetica-Bold',
                borderPadding=(0, 0, 5, 0)
            ),
            'Heading2': ParagraphStyle(
                'CustomH2',
                parent=base_styles['Heading2'],
                fontSize=14,
                textColor=Colors.SECONDARY,
                spaceBefore=15,
                spaceAfter=8,
                fontName='Helvetica-Bold'
            ),
            'Heading3': ParagraphStyle(
                'CustomH3',
                parent=base_styles['Heading3'],
                fontSize=12,
                textColor=Colors.TEXT,
                spaceBefore=10,
                spaceAfter=6,
                fontName='Helvetica-Bold'
            ),
            'Body': ParagraphStyle(
                'CustomBody',
                parent=base_styles['Normal'],
                fontSize=10,
                textColor=Colors.TEXT,
                leading=14,
                alignment=TA_JUSTIFY,
                spaceAfter=8
            ),
            'BodySmall': ParagraphStyle(
                'CustomBodySmall',
                parent=base_styles['Normal'],
                fontSize=9,
                textColor=Colors.TEXT_LIGHT,
                leading=12,
                spaceAfter=6
            ),
            'Finding': ParagraphStyle(
                'Finding',
                parent=base_styles['Normal'],
                fontSize=10,
                textColor=Colors.TEXT,
                leading=14,
                leftIndent=15,
                spaceAfter=4
            ),
            'KeyGap': ParagraphStyle(
                'KeyGap',
                parent=base_styles['Normal'],
                fontSize=10,
                textColor=Colors.DANGER,
                leading=14,
                leftIndent=15,
                spaceAfter=4,
                fontName='Helvetica-Bold'
            ),
            'Recommendation': ParagraphStyle(
                'Recommendation',
                parent=base_styles['Normal'],
                fontSize=10,
                textColor=Colors.SUCCESS,
                leading=14,
                leftIndent=15,
                spaceAfter=4
            ),
            'Footer': ParagraphStyle(
                'Footer',
                parent=base_styles['Normal'],
                fontSize=8,
                textColor=Colors.TEXT_LIGHT,
                alignment=TA_CENTER
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
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm
        )
        
        # Build story
        story = self._build_story(lead)
        
        # Build PDF with header/footer
        doc.build(story, onFirstPage=self._add_header_footer, onLaterPages=self._add_header_footer)
        
        return output_path
    
    def _add_header_footer(self, canvas, doc):
        """Add header and footer to each page."""
        canvas.saveState()
        
        # Header line
        canvas.setStrokeColor(Colors.PRIMARY)
        canvas.setLineWidth(2)
        canvas.line(2*cm, A4[1] - 1.5*cm, A4[0] - 2*cm, A4[1] - 1.5*cm)
        
        # Footer
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(Colors.TEXT_LIGHT)
        footer_text = f"Security Assessment Report | Generated {self.generated_at.strftime('%Y-%m-%d %H:%M')} | Confidential"
        canvas.drawCentredString(A4[0]/2, 1*cm, footer_text)
        
        # Page number
        page_num = canvas.getPageNumber()
        canvas.drawRightString(A4[0] - 2*cm, 1*cm, f"Page {page_num}")
        
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
        elements.append(Spacer(1, 3*cm))
        
        # Company name as main title
        elements.append(Paragraph(
            f"Security Assessment Report",
            self.styles['Title']
        ))
        
        elements.append(Spacer(1, 0.5*cm))
        
        # Company name
        elements.append(Paragraph(
            f"<b>{lead.company_name}</b>",
            ParagraphStyle(
                'CompanyName',
                fontSize=24,
                textColor=Colors.ACCENT,
                spaceAfter=10
            )
        ))
        
        # Domain
        elements.append(Paragraph(
            f"{lead.domain}",
            self.styles['Subtitle']
        ))
        
        elements.append(Spacer(1, 1*cm))
        
        # Horizontal rule
        elements.append(HRFlowable(
            width="100%",
            thickness=2,
            color=Colors.PRIMARY,
            spaceAfter=1*cm
        ))
        
        # Company info table
        info_data = [
            ["Sector:", lead.sector],
            ["Assessment Date:", self.generated_at.strftime("%B %d, %Y")],
        ]
        
        if lead.nis2_covered:
            info_data.append(["NIS2 Status:", f"Covered ({lead.nis2_entity_type or 'Entity'})"])
        
        info_table = Table(info_data, colWidths=[4*cm, 8*cm])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('TEXTCOLOR', (0, 0), (0, -1), Colors.TEXT_LIGHT),
            ('TEXTCOLOR', (1, 0), (1, -1), Colors.TEXT),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ]))
        elements.append(info_table)
        
        elements.append(Spacer(1, 2*cm))
        
        # Overall score box
        tier_color = self._get_tier_color(lead.tier)
        tier_label = lead.tier.value.replace("🔴 ", "").replace("🟠 ", "").replace("🟢 ", "")
        
        score_data = [[
            Paragraph(f"<b>Overall Security Score</b>", ParagraphStyle('ScoreLabel', fontSize=12, textColor=Colors.WHITE)),
        ], [
            Paragraph(f"<b>{lead.total_score:.1f}</b> / 18", ParagraphStyle('ScoreValue', fontSize=36, textColor=Colors.WHITE, alignment=TA_CENTER)),
        ], [
            Paragraph(f"<b>{tier_label}</b>", ParagraphStyle('TierLabel', fontSize=14, textColor=Colors.WHITE, alignment=TA_CENTER)),
        ]]
        
        score_table = Table(score_data, colWidths=[8*cm])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), tier_color),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 15),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
            ('LEFTPADDING', (0, 0), (-1, -1), 20),
            ('RIGHTPADDING', (0, 0), (-1, -1), 20),
            ('ROUNDEDCORNERS', [10, 10, 10, 10]),
        ]))
        elements.append(score_table)
        
        elements.append(Spacer(1, 2*cm))
        
        # Disclaimer
        elements.append(Paragraph(
            "<i>This report is based on publicly available information and passive scanning techniques. "
            "No active penetration testing or vulnerability exploitation was performed. "
            "This assessment is intended for informational purposes only.</i>",
            self.styles['BodySmall']
        ))
        
        return elements
    
    def _build_executive_summary(self, lead: LeadScore) -> List:
        """Build the executive summary section."""
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['Heading1']))
        elements.append(HRFlowable(width="100%", thickness=1, color=Colors.ACCENT, spaceAfter=0.5*cm))
        
        # Summary paragraph
        tier_text = self._get_tier_description(lead.tier)
        elements.append(Paragraph(
            f"This security assessment of <b>{lead.company_name}</b> ({lead.domain}) identified "
            f"<b>{lead.findings_count} findings</b> across nine key security dimensions. "
            f"The overall security posture is rated as <b>{tier_text}</b> with a score of "
            f"<b>{lead.total_score:.1f}/18</b>.",
            self.styles['Body']
        ))
        
        # NIS2 context if applicable
        if lead.nis2_covered:
            elements.append(Spacer(1, 0.5*cm))
            elements.append(Paragraph(
                f"⚠️ <b>NIS2 Compliance Note:</b> Based on the sector ({lead.sector}) and company size, "
                f"{lead.company_name} appears to fall under NIS2 directive scope as a "
                f"<b>{lead.nis2_entity_type or 'covered entity'}</b>. This has implications for "
                f"cybersecurity requirements, incident reporting, and potential penalties for non-compliance.",
                ParagraphStyle('NIS2Alert', parent=self.styles['Body'], backColor=colors.HexColor('#fef3c7'), leftIndent=10, rightIndent=10, spaceBefore=10, spaceAfter=10)
            ))
        
        elements.append(Spacer(1, 0.5*cm))
        
        # Score breakdown table
        elements.append(Paragraph("Security Dimension Scores", self.styles['Heading2']))
        
        dimensions = [
            ("Email Security", lead.email_security),
            ("Technical Hygiene", lead.technical_hygiene),
            ("TLS/SSL Certificate", lead.tls_certificate),
            ("HTTP Security Headers", lead.http_headers),
            ("Cookie Compliance", lead.cookie_compliance),
            ("Attack Surface", lead.attack_surface),
            ("Technology Stack", lead.tech_stack),
            ("Security Communication", lead.security_communication),
            ("NIS2 Readiness", lead.nis2_readiness),
        ]
        
        score_data = [["Dimension", "Score", "Status"]]
        for name, dim in dimensions:
            if dim:
                status_color = self._get_score_color(dim.score)
                status = "🟢 Good" if dim.score == 2 else ("🟡 Needs Work" if dim.score == 1 else "🔴 Critical")
                score_data.append([name, f"{dim.score}/2", status])
            else:
                score_data.append([name, "N/A", "⚪ Not Scanned"])
        
        score_table = Table(score_data, colWidths=[7*cm, 3*cm, 4*cm])
        score_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BACKGROUND', (0, 0), (-1, 0), Colors.PRIMARY),
            ('TEXTCOLOR', (0, 0), (-1, 0), Colors.WHITE),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, Colors.TEXT_LIGHT),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [Colors.WHITE, colors.HexColor('#f7fafc')]),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(score_table)
        
        elements.append(Spacer(1, 1*cm))
        
        # Key gaps
        if lead.key_gaps:
            elements.append(Paragraph("Key Security Gaps", self.styles['Heading2']))
            for gap in lead.key_gaps[:5]:  # Top 5 gaps
                elements.append(Paragraph(f"• {gap}", self.styles['KeyGap']))
        
        return elements
    
    def _build_detailed_findings(self, lead: LeadScore) -> List:
        """Build the detailed findings section."""
        elements = []
        
        elements.append(Paragraph("Detailed Findings", self.styles['Heading1']))
        elements.append(HRFlowable(width="100%", thickness=1, color=Colors.ACCENT, spaceAfter=0.5*cm))
        
        # Email Security
        elements.extend(self._build_dimension_section(
            "Email Security",
            lead.email_security,
            lead.dns_result,
            "Email security protects against phishing, spoofing, and business email compromise (BEC) attacks. "
            "SPF, DKIM, and DMARC are industry-standard protocols that validate email authenticity.",
            self._get_email_findings(lead),
            [
                "Implement DMARC with a policy of 'reject' to prevent email spoofing",
                "Configure SPF records to authorize legitimate mail servers",
                "Enable DKIM signing for all outgoing emails",
                "Monitor DMARC reports to detect unauthorized email sources"
            ]
        ))
        
        elements.append(Spacer(1, 0.5*cm))
        
        # TLS/SSL
        elements.extend(self._build_dimension_section(
            "TLS/SSL Certificate Security",
            lead.tls_certificate,
            lead.ssl_result,
            "TLS certificates encrypt data in transit and establish trust with visitors. "
            "Expired, misconfigured, or weak certificates can expose data and damage reputation.",
            self._get_ssl_findings(lead),
            [
                "Ensure certificates are renewed well before expiration",
                "Use TLS 1.2 or higher, disable older protocols",
                "Implement certificate transparency monitoring",
                "Consider using certificates with Extended Validation (EV)"
            ]
        ))
        
        elements.append(Spacer(1, 0.5*cm))
        
        # HTTP Headers
        elements.extend(self._build_dimension_section(
            "HTTP Security Headers",
            lead.http_headers,
            lead.headers_result,
            "Security headers protect against common web attacks like XSS, clickjacking, and MIME sniffing. "
            "They are easy to implement and provide significant defense-in-depth protection.",
            self._get_headers_findings(lead),
            [
                "Implement Content-Security-Policy (CSP) to prevent XSS attacks",
                "Add X-Frame-Options or frame-ancestors to prevent clickjacking",
                "Enable HSTS with a long max-age to enforce HTTPS",
                "Configure X-Content-Type-Options to prevent MIME sniffing"
            ]
        ))
        
        elements.append(Spacer(1, 0.5*cm))
        
        # Cookie Compliance
        elements.extend(self._build_dimension_section(
            "Cookie Compliance",
            lead.cookie_compliance,
            lead.cookie_result,
            "Cookie compliance relates to GDPR requirements for user consent and proper cookie security attributes. "
            "Non-compliant cookie practices can result in regulatory fines and user privacy violations.",
            self._get_cookie_findings(lead),
            [
                "Implement a cookie consent mechanism compliant with GDPR",
                "Set Secure and HttpOnly flags on sensitive cookies",
                "Use SameSite attribute to prevent CSRF attacks",
                "Document all cookies and their purposes in a privacy policy"
            ]
        ))
        
        elements.append(Spacer(1, 0.5*cm))
        
        # Attack Surface
        elements.extend(self._build_dimension_section(
            "Attack Surface",
            lead.attack_surface,
            lead.subdomain_result,
            "Attack surface refers to all points where an attacker could try to enter or extract data. "
            "Subdomains, exposed services, and forgotten infrastructure expand the attack surface.",
            self._get_subdomain_findings(lead),
            [
                "Inventory all subdomains and decommission unused ones",
                "Implement consistent security controls across all subdomains",
                "Monitor certificate transparency logs for new certificates",
                "Regular security assessments of all exposed services"
            ]
        ))
        
        return elements
    
    def _build_dimension_section(
        self,
        title: str,
        dimension,
        raw_result,
        explanation: str,
        findings: List[str],
        recommendations: List[str]
    ) -> List:
        """Build a section for a security dimension."""
        elements = []
        
        # Section header with score
        if dimension:
            score_color = self._get_score_color(dimension.score)
            score_text = f"Score: {dimension.score}/2"
        else:
            score_color = Colors.TEXT_LIGHT
            score_text = "Not Assessed"
        
        elements.append(Paragraph(f"<b>{title}</b> ({score_text})", self.styles['Heading2']))
        
        # Explanation
        elements.append(Paragraph(explanation, self.styles['Body']))
        
        # Findings
        if findings:
            elements.append(Paragraph("<b>Findings:</b>", self.styles['Heading3']))
            for finding in findings:
                elements.append(Paragraph(f"• {finding}", self.styles['Finding']))
        
        # Dimension-specific description
        if dimension and dimension.description:
            elements.append(Spacer(1, 0.3*cm))
            elements.append(Paragraph(f"<i>Assessment: {dimension.description}</i>", self.styles['BodySmall']))
        
        # Recommendations
        elements.append(Paragraph("<b>Recommendations:</b>", self.styles['Heading3']))
        for rec in recommendations[:3]:  # Top 3 recommendations
            elements.append(Paragraph(f"✓ {rec}", self.styles['Recommendation']))
        
        return elements
    
    def _build_recommendations(self, lead: LeadScore) -> List:
        """Build the recommendations section."""
        elements = []
        
        elements.append(Spacer(1, 1*cm))
        elements.append(Paragraph("Recommendations Summary", self.styles['Heading1']))
        elements.append(HRFlowable(width="100%", thickness=1, color=Colors.ACCENT, spaceAfter=0.5*cm))
        
        elements.append(Paragraph(
            "Based on the assessment findings, the following prioritized actions are recommended:",
            self.styles['Body']
        ))
        
        # Priority actions based on sales angles
        if lead.sales_angles:
            elements.append(Spacer(1, 0.5*cm))
            elements.append(Paragraph("Priority Actions", self.styles['Heading2']))
            
            for i, angle in enumerate(lead.sales_angles[:5], 1):
                elements.append(Paragraph(
                    f"<b>{i}.</b> {angle}",
                    self.styles['Body']
                ))
        
        # General recommendations
        elements.append(Spacer(1, 0.5*cm))
        elements.append(Paragraph("General Security Recommendations", self.styles['Heading2']))
        
        general_recs = [
            "Conduct regular security assessments and penetration tests",
            "Implement a security awareness training program for employees",
            "Establish an incident response plan and test it regularly",
            "Review and update security policies on an annual basis",
            "Consider engaging a managed security service provider (MSSP)"
        ]
        
        for rec in general_recs:
            elements.append(Paragraph(f"• {rec}", self.styles['Body']))
        
        # NIS2 specific if applicable
        if lead.nis2_covered:
            elements.append(Spacer(1, 0.5*cm))
            elements.append(Paragraph("NIS2 Compliance Actions", self.styles['Heading2']))
            
            nis2_recs = [
                "Assess current cybersecurity measures against NIS2 requirements",
                "Establish incident reporting procedures (24h/72h requirements)",
                "Implement supply chain security risk management",
                "Ensure management accountability for cybersecurity",
                "Prepare for potential regulatory audits and supervision"
            ]
            
            for rec in nis2_recs:
                elements.append(Paragraph(f"• {rec}", self.styles['Body']))
        
        return elements
    
    def _build_technical_appendix(self, lead: LeadScore) -> List:
        """Build the comprehensive technical appendix with all factual scan data (Dutch)."""
        elements = []

        elements.append(Paragraph("Technical Appendix", self.styles['Heading1']))
        elements.append(HRFlowable(width="100%", thickness=1, color=Colors.ACCENT, spaceAfter=0.5*cm))

        elements.append(Paragraph(
            "Deze bijlage bevat alle feitelijke technische data uit de security assessment. "
            "Per dimensie die <b>rood</b> of <b>oranje</b> scoort is een gedetailleerd blok opgenomen "
            "met alle gevonden informatie.",
            self.styles['Body']
        ))

        # Collect dimensions that scored RED (0) or ORANGE (1)
        dimensions_to_detail = []
        dim_map = [
            ("vuln", "Bekende Kwetsbaarheden", lead.technical_hygiene, lead.shodan_result),
            ("email", "E-mail Beveiliging", lead.email_security, lead.dns_result),
            ("headers", "Security Headers", lead.http_headers, lead.headers_result),
            ("subdomains", "Aanvalsoppervlak / Subdomains", lead.attack_surface, lead.subdomain_result),
            ("ssl", "TLS/SSL Certificaat", lead.tls_certificate, lead.ssl_result),
            ("admin", "Admin Panels", lead.admin_panel, lead.admin_result),
            ("governance", "Security Governance", lead.security_governance, lead.governance_result),
            ("techstack", "Tech Stack", lead.tech_stack, lead.techstack_result),
        ]

        for key, title, dim, raw in dim_map:
            if dim and dim.score <= 1:
                # Skip dimensions without useful data (e.g. scan timed out, 0 results)
                if key == "subdomains" and raw and (raw.total_count or 0) == 0 and not raw.risky_subdomains:
                    continue
                if key == "vuln" and raw and not raw.vulns and not raw.risky_ports:
                    continue
                dimensions_to_detail.append((key, title, dim, raw))

        if not dimensions_to_detail:
            elements.append(Paragraph(
                "Alle dimensies scoren groen — er zijn geen detail-blokken vereist.",
                self.styles['Body']
            ))
        else:
            for key, title, dim, raw in dimensions_to_detail:
                score_label = "KRITIEK" if dim.score == 0 else "AANDACHT NODIG"
                score_color = Colors.DANGER if dim.score == 0 else Colors.WARNING

                elements.append(Spacer(1, 0.5*cm))
                elements.append(Paragraph(
                    f'<font color="{score_color.hexval()}">\u25cf</font> <b>{title}</b>  '
                    f'<font color="{score_color.hexval()}" size="9">({score_label} — {dim.score}/2)</font>',
                    self.styles['Heading2']
                ))

                if key == "vuln":
                    elements.extend(self._appendix_vulnerabilities(lead))
                elif key == "email":
                    elements.extend(self._appendix_email(lead))
                elif key == "headers":
                    elements.extend(self._appendix_headers(lead))
                elif key == "subdomains":
                    elements.extend(self._appendix_subdomains(lead))
                elif key == "ssl":
                    elements.extend(self._appendix_ssl(lead))
                elif key == "admin":
                    elements.extend(self._appendix_admin(lead))
                elif key == "governance":
                    elements.extend(self._appendix_governance(lead))
                elif key == "techstack":
                    elements.extend(self._appendix_techstack(lead))

        # Methodology (always included)
        elements.append(PageBreak())
        elements.append(Paragraph("Assessment Methodologie", self.styles['Heading2']))
        elements.append(Paragraph(
            "Dit assessment is uitgevoerd met uitsluitend passieve reconnaissance-technieken. "
            "Er is geen actieve penetratietest of exploitatie uitgevoerd. Gebruikte bronnen:",
            self.styles['Body']
        ))
        methodology_items = [
            "DNS record queries (SPF, DMARC, DKIM, MX, TXT)",
            "SSL/TLS certificaat-analyse",
            "HTTP response header inspectie",
            "Shodan InternetDB (open poorten, CVEs, services)",
            "Certificate Transparency logs (crt.sh) voor subdomain-discovery",
            "Publieke website-analyse (tech stack, admin panels, governance)",
            "Cookie- en consent-mechanisme inspectie",
        ]
        for item in methodology_items:
            elements.append(Paragraph(f"\u2022 {item}", self.styles['BodySmall']))

        return elements

    # ------------------------------------------------------------------
    # Appendix detail builders per dimension
    # ------------------------------------------------------------------

    def _appendix_vulnerabilities(self, lead: LeadScore) -> List:
        """Bekende Kwetsbaarheden detail block."""
        elements = []
        shodan = lead.shodan_result

        if not shodan:
            elements.append(Paragraph("<i>Shodan-scan niet beschikbaar.</i>", self.styles['BodySmall']))
            return elements

        # Server IP
        elements.append(Paragraph(f"<b>Server IP:</b> {shodan.ip_address or 'Onbekend'}", self.styles['Body']))

        # Detected software (CPEs)
        if shodan.cpes:
            elements.append(Paragraph("<b>Gedetecteerde software (CPE):</b>", self.styles['Body']))
            for cpe in shodan.cpes:
                elements.append(Paragraph(f"\u2022 {cpe}", self.styles['BodySmall']))
        else:
            elements.append(Paragraph("<b>Gedetecteerde software:</b> Geen CPE-informatie beschikbaar", self.styles['Body']))

        # CVEs
        if shodan.vulns:
            elements.append(Spacer(1, 0.3*cm))
            elements.append(Paragraph(f"<b>Totaal aantal CVEs:</b> {len(shodan.vulns)}", self.styles['Body']))
            cve_data = [["CVE", "Bron"]]
            for cve_id in shodan.vulns[:10]:
                cve_data.append([str(cve_id), "Shodan InternetDB"])
            cve_table = Table(cve_data, colWidths=[5*cm, 9*cm])
            cve_table.setStyle(self._detail_table_style(len(cve_data)))
            elements.append(cve_table)
            if len(shodan.vulns) > 10:
                elements.append(Paragraph(
                    f"<i>... en {len(shodan.vulns) - 10} overige CVEs (volledige lijst beschikbaar op aanvraag)</i>",
                    self.styles['BodySmall']
                ))
        else:
            elements.append(Paragraph("<b>CVEs:</b> Geen bekende kwetsbaarheden gevonden", self.styles['Body']))

        # Open ports
        if shodan.ports:
            elements.append(Spacer(1, 0.3*cm))
            port_data = [["Poort", "Service", "Risico"]]
            risky_set = set(shodan.risky_ports or [])
            for port in sorted(shodan.ports):
                service = shodan.risky_ports_detail.get(port, self._port_service_name(port))
                if port in risky_set:
                    risk = "HOOG RISICO"
                else:
                    risk = "Normaal"
                port_data.append([str(port), service, risk])
            port_table = Table(port_data, colWidths=[3*cm, 7*cm, 4*cm])
            style = self._detail_table_style(len(port_data))
            # Color risky rows
            for i, port in enumerate(sorted(shodan.ports), 1):
                if port in risky_set:
                    style.add('TEXTCOLOR', (2, i), (2, i), Colors.DANGER)
                    style.add('FONTNAME', (2, i), (2, i), 'Helvetica-Bold')
            port_table.setStyle(style)
            elements.append(Paragraph("<b>Open poorten:</b>", self.styles['Body']))
            elements.append(port_table)
        else:
            elements.append(Paragraph("<b>Open poorten:</b> Geen open poorten gedetecteerd", self.styles['Body']))

        # Risky ports explanation
        if shodan.risky_ports:
            elements.append(Spacer(1, 0.3*cm))
            elements.append(Paragraph("<b>Risicovolle poorten — toelichting:</b>", self.styles['Body']))
            for port in shodan.risky_ports:
                detail = shodan.risky_ports_detail.get(port, "")
                elements.append(Paragraph(
                    f'\u2022 <font color="{Colors.DANGER.hexval()}"><b>Poort {port}</b></font>: {detail}',
                    self.styles['Finding']
                ))

        return elements

    def _appendix_email(self, lead: LeadScore) -> List:
        """E-mail Beveiliging detail block."""
        elements = []
        dns = lead.dns_result

        if not dns:
            elements.append(Paragraph("<i>DNS-scan niet beschikbaar.</i>", self.styles['BodySmall']))
            return elements

        # SPF
        has_spf = bool(dns.spf_record)
        spf_policy = dns.spf_policy or "missing"
        spf_color = Colors.SUCCESS if dns.spf_score == 2 else (Colors.WARNING if dns.spf_score == 1 else Colors.DANGER)
        elements.append(Paragraph(f"<b>SPF Record:</b>", self.styles['Body']))
        elements.append(Paragraph(
            f"{dns.spf_record or 'Niet geconfigureerd'}",
            self.styles['BodySmall']
        ))
        spf_assessment = "hard fail (-all) — goed" if "-all" in (dns.spf_record or "") else (
            "soft fail (~all) — zwak" if "~all" in (dns.spf_record or "") else (
                "ontbreekt — geen bescherming" if not has_spf else spf_policy
            ))
        elements.append(Paragraph(
            f'<font color="{spf_color.hexval()}">Beoordeling: {spf_assessment}</font>',
            self.styles['BodySmall']
        ))

        elements.append(Spacer(1, 0.2*cm))

        # DMARC
        has_dmarc = bool(dns.dmarc_record)
        dmarc_policy = dns.dmarc_policy or "missing"
        dmarc_color = Colors.SUCCESS if dns.dmarc_score == 2 else (Colors.WARNING if dns.dmarc_score == 1 else Colors.DANGER)
        elements.append(Paragraph(f"<b>DMARC Record:</b>", self.styles['Body']))
        elements.append(Paragraph(
            f"{dns.dmarc_record or 'Niet geconfigureerd'}",
            self.styles['BodySmall']
        ))
        dmarc_assessment = {
            "reject": "reject — goed, foutieve mails worden geweigerd",
            "quarantine": "quarantine — matig, foutieve mails gaan naar spam",
            "none (monitoring only)": "none — alleen monitoring, geen handhaving",
            "missing": "ontbreekt — geen DMARC-bescherming",
        }.get(dmarc_policy, dmarc_policy)
        elements.append(Paragraph(
            f'<font color="{dmarc_color.hexval()}">Beoordeling: {dmarc_assessment}</font>',
            self.styles['BodySmall']
        ))

        elements.append(Spacer(1, 0.2*cm))

        # DKIM
        dkim_color = Colors.SUCCESS if dns.dkim_found else Colors.DANGER
        elements.append(Paragraph(f"<b>DKIM:</b>", self.styles['Body']))
        if dns.dkim_found:
            elements.append(Paragraph(
                f'<font color="{dkim_color.hexval()}">Gevonden</font> (selector: {dns.dkim_selector or "onbekend"})',
                self.styles['BodySmall']
            ))
        else:
            elements.append(Paragraph(
                f'<font color="{dkim_color.hexval()}">Niet gevonden</font> — gezocht bij selectors: '
                f'google, selector1, selector2, default, mail, k1, dkim, s1, s2, protonmail, etc.',
                self.styles['BodySmall']
            ))

        elements.append(Spacer(1, 0.3*cm))

        # Risk explanation
        if not has_dmarc or dmarc_policy in ("missing", "none (monitoring only)"):
            elements.append(Paragraph(
                f'<font color="{Colors.DANGER.hexval()}"><b>Risico-uitleg:</b></font> '
                f'Met de huidige configuratie kan iemand een e-mail sturen als ceo@{lead.domain} '
                f'aan elke willekeurige ontvanger. De ontvanger ziet geen verschil met een echt bericht.',
                self.styles['Body']
            ))

        elements.append(Paragraph(
            "<b>Verificatie:</b> Controleerbaar via MXToolbox.com — voer het domein in en bekijk de DMARC-status.",
            self.styles['BodySmall']
        ))

        return elements

    def _appendix_headers(self, lead: LeadScore) -> List:
        """Security Headers detail block."""
        elements = []
        hdr = lead.headers_result

        if not hdr:
            elements.append(Paragraph("<i>Header-scan niet beschikbaar.</i>", self.styles['BodySmall']))
            return elements

        elements.append(Paragraph(f"<b>Grade:</b> {hdr.grade}", self.styles['Body']))

        hp = hdr.headers_present or {}

        # Present headers
        present_list = [h for h in hp.keys()]
        if present_list:
            elements.append(Paragraph("<b>Aanwezige headers:</b>", self.styles['Body']))
            for h in present_list:
                elements.append(Paragraph(
                    f'\u2022 <font color="{Colors.SUCCESS.hexval()}">{h}</font>: {str(hp[h])[:80]}',
                    self.styles['BodySmall']
                ))

        # Missing headers with risk explanation (Dutch)
        header_risks = {
            "Strict-Transport-Security": "Verkeer kan onderschept worden op onveilige verbindingen",
            "Content-Security-Policy": "Kwaadaardige scripts kunnen ge\u00efnjecteerd worden (XSS)",
            "X-Frame-Options": "Website kan in onzichtbaar frame geladen worden (clickjacking)",
            "X-Content-Type-Options": "Browser kan bestanden verkeerd interpreteren als uitvoerbare code",
            "Referrer-Policy": "Interne URLs en sessie-informatie lekken naar externe partijen",
            "Permissions-Policy": "Ge\u00efnjecteerde code kan camera/microfoon/locatie aanvragen",
        }
        missing = hdr.headers_missing or []
        # Also check standard headers not in headers_present
        for std_header in header_risks:
            if std_header not in hp and std_header not in missing:
                missing.append(std_header)

        if missing:
            elements.append(Spacer(1, 0.3*cm))
            miss_data = [["Header", "Status", "Risico"]]
            for h in missing:
                risk = header_risks.get(h, "Beveiligingsrisico")
                miss_data.append([h, "Ontbreekt", risk])
            miss_table = Table(miss_data, colWidths=[5*cm, 2.5*cm, 9*cm])
            style = self._detail_table_style(len(miss_data))
            # Color the Status column red
            for i in range(1, len(miss_data)):
                style.add('TEXTCOLOR', (1, i), (1, i), Colors.DANGER)
                style.add('FONTNAME', (1, i), (1, i), 'Helvetica-Bold')
            miss_table.setStyle(style)
            elements.append(Paragraph("<b>Ontbrekende headers:</b>", self.styles['Body']))
            elements.append(miss_table)

        # Info leakage
        if hdr.info_leakage:
            elements.append(Spacer(1, 0.3*cm))
            elements.append(Paragraph("<b>Informatie-lekkage via headers:</b>", self.styles['Body']))
            for header_name, value in hdr.info_leakage.items():
                elements.append(Paragraph(
                    f'\u2022 <font color="{Colors.WARNING.hexval()}">{header_name}</font>: {value}',
                    self.styles['BodySmall']
                ))

        return elements

    def _appendix_subdomains(self, lead: LeadScore) -> List:
        """Aanvalsoppervlak / Subdomains detail block."""
        elements = []
        sub = lead.subdomain_result

        if not sub:
            elements.append(Paragraph("<i>Subdomain-scan niet beschikbaar.</i>", self.styles['BodySmall']))
            return elements

        total = sub.total_count or len(sub.subdomains_found or [])
        elements.append(Paragraph(f"<b>Totaal subdomains gevonden:</b> {total}", self.styles['Body']))

        # Risky subdomains table
        if sub.risky_subdomains:
            risky_data = [["Subdomain", "Type", "Risico"]]
            for risky in sub.risky_subdomains:
                if isinstance(risky, dict):
                    name = risky.get('subdomain', risky.get('name', str(risky)))
                    rtype = risky.get('type', risky.get('category', ''))
                    risk = risky.get('risk', risky.get('description', ''))
                else:
                    name = str(risky)
                    rtype = ""
                    risk = ""
                risky_data.append([name, rtype, risk])

            risky_table = Table(risky_data, colWidths=[5.5*cm, 3*cm, 7.5*cm])
            style = self._detail_table_style(len(risky_data))
            risky_table.setStyle(style)
            elements.append(Spacer(1, 0.3*cm))
            elements.append(Paragraph("<b>Risicovolle subdomains:</b>", self.styles['Body']))
            elements.append(risky_table)

        # Neutral subdomains summary
        neutral_count = len(sub.neutral_subdomains or [])
        if neutral_count > 0:
            elements.append(Spacer(1, 0.2*cm))
            elements.append(Paragraph(
                f"<b>Niet-risicovolle subdomains:</b> {neutral_count} reguliere subdomains "
                f"(www, mail, cdn, etc.)",
                self.styles['Body']
            ))

        return elements

    def _appendix_ssl(self, lead: LeadScore) -> List:
        """TLS/SSL Certificaat detail block."""
        elements = []
        ssl = lead.ssl_result

        if not ssl:
            elements.append(Paragraph("<i>SSL-scan niet beschikbaar.</i>", self.styles['BodySmall']))
            return elements

        # Certificate info table
        valid_text = "Ja" if ssl.certificate_valid else "Nee"
        valid_color = Colors.SUCCESS if ssl.certificate_valid else Colors.DANGER

        not_before_str = str(ssl.not_before) if ssl.not_before else "Onbekend"
        not_after_str = str(ssl.not_after) if ssl.not_after else "Onbekend"

        days_text = str(ssl.days_until_expiry) if ssl.days_until_expiry is not None else "N/A"
        if ssl.days_until_expiry is not None and ssl.days_until_expiry < 90:
            days_text += "  ⚠️ WAARSCHUWING: minder dan 90 dagen"

        protocol = ssl.protocol_version or "Onbekend"

        ssl_data = [
            ["Eigenschap", "Waarde"],
            ["Certificaat geldig", valid_text],
            ["Issuer", ssl.issuer or "Onbekend"],
            ["Geldig van", not_before_str],
            ["Geldig tot", not_after_str],
            ["Dagen tot expiry", days_text],
            ["Protocol", protocol],
        ]

        if ssl.san_domains:
            ssl_data.append(["SAN Domains", ", ".join(ssl.san_domains[:10]) + (
                f" (+{len(ssl.san_domains)-10} meer)" if len(ssl.san_domains) > 10 else ""
            )])

        ssl_table = Table(ssl_data, colWidths=[5*cm, 9*cm])
        style = self._detail_table_style(len(ssl_data))
        # Color the valid row
        if not ssl.certificate_valid:
            style.add('TEXTCOLOR', (1, 1), (1, 1), Colors.DANGER)
            style.add('FONTNAME', (1, 1), (1, 1), 'Helvetica-Bold')
        ssl_table.setStyle(style)
        elements.append(ssl_table)

        # Weak points
        weak_points = []
        if protocol and ("1.0" in protocol or "1.1" in protocol):
            weak_points.append(f"Verouderd protocol ({protocol}) — TLS 1.0/1.1 is onveilig en deprecated")
        if ssl.issuer and "self" in (ssl.issuer or "").lower():
            weak_points.append("Self-signed certificaat — niet vertrouwd door browsers")
        if ssl.days_until_expiry is not None and ssl.days_until_expiry <= 0:
            weak_points.append("Certificaat is VERLOPEN")
        elif ssl.days_until_expiry is not None and ssl.days_until_expiry < 30:
            weak_points.append(f"Certificaat verloopt binnen {ssl.days_until_expiry} dagen")

        if weak_points:
            elements.append(Spacer(1, 0.3*cm))
            elements.append(Paragraph("<b>Zwakke punten:</b>", self.styles['Body']))
            for wp in weak_points:
                elements.append(Paragraph(
                    f'\u2022 <font color="{Colors.DANGER.hexval()}">{wp}</font>',
                    self.styles['Finding']
                ))

        return elements

    def _appendix_admin(self, lead: LeadScore) -> List:
        """Admin Panels detail block."""
        elements = []
        admin = lead.admin_result

        if not admin:
            elements.append(Paragraph("<i>Admin-scan niet beschikbaar.</i>", self.styles['BodySmall']))
            return elements

        # Found admin/login pages
        all_pages = (admin.admin_pages_found or []) + (admin.login_pages_found or [])
        if all_pages:
            admin_data = [["URL", "Type", "MFA detectie", "Risico"]]
            for page in all_pages:
                if isinstance(page, dict):
                    url = page.get('url', page.get('path', str(page)))
                    ptype = page.get('type', page.get('category', 'Admin'))
                    mfa = page.get('mfa', 'Niet gedetecteerd')
                    risk = page.get('risk', 'Brute-force, credential stuffing')
                else:
                    url = str(page)
                    ptype = "Admin/Login"
                    mfa = "Niet gedetecteerd"
                    risk = "Brute-force, credential stuffing"
                admin_data.append([
                    Paragraph(str(url), self.styles['BodySmall']),
                    ptype, mfa, risk
                ])
            admin_table = Table(admin_data, colWidths=[5.5*cm, 3*cm, 3.5*cm, 4*cm])
            admin_table.setStyle(self._detail_table_style(len(admin_data)))
            elements.append(Paragraph("<b>Gevonden admin/login pagina's:</b>", self.styles['Body']))
            elements.append(admin_table)

            # MFA / SSO info
            if admin.mfa_indicators:
                elements.append(Spacer(1, 0.2*cm))
                elements.append(Paragraph("<b>MFA indicatoren:</b> " + ", ".join(admin.mfa_indicators), self.styles['Body']))
            if admin.sso_providers_detected:
                elements.append(Paragraph("<b>SSO providers:</b> " + ", ".join(admin.sso_providers_detected), self.styles['Body']))
        else:
            elements.append(Paragraph("<b>Gevonden admin pagina's:</b> Geen publiek toegankelijke admin/login pagina's gevonden.", self.styles['Body']))

        # Paths checked
        if admin.pages_checked:
            elements.append(Spacer(1, 0.3*cm))
            elements.append(Paragraph(
                f"<b>Gecontroleerde paden ({len(admin.pages_checked)}):</b> "
                f"{', '.join(admin.pages_checked[:20])}"
                f"{'...' if len(admin.pages_checked) > 20 else ''}",
                self.styles['BodySmall']
            ))

        return elements

    def _appendix_governance(self, lead: LeadScore) -> List:
        """Security Governance detail block."""
        elements = []
        gov = lead.governance_result

        if not gov:
            elements.append(Paragraph("<i>Governance-scan niet beschikbaar.</i>", self.styles['BodySmall']))
            return elements

        # CISO / Security Officer
        ciso_color = Colors.SUCCESS if gov.has_visible_ciso else Colors.DANGER
        ciso_text = "Ja" if gov.has_visible_ciso else "Nee"
        elements.append(Paragraph(
            f'<b>CISO/Security Officer zichtbaar:</b> <font color="{ciso_color.hexval()}">{ciso_text}</font>',
            self.styles['Body']
        ))

        if gov.security_leaders_found:
            elements.append(Paragraph(
                "<b>Gevonden security-functies:</b> " + ", ".join(gov.security_leaders_found),
                self.styles['BodySmall']
            ))
        if gov.security_titles_found:
            elements.append(Paragraph(
                "<b>Gevonden titels:</b> " + ", ".join(gov.security_titles_found),
                self.styles['BodySmall']
            ))

        # Where searched
        if gov.pages_checked:
            elements.append(Paragraph(
                "<b>Waar gezocht:</b> " + ", ".join(gov.pages_checked[:10]),
                self.styles['BodySmall']
            ))

        elements.append(Spacer(1, 0.2*cm))

        # Annual report
        if gov.annual_report_found:
            elements.append(Paragraph(
                f"<b>Jaarverslag gevonden:</b> Ja"
                f"{' — ' + gov.annual_report_url if gov.annual_report_url else ''}"
                f"{' (' + gov.annual_report_year + ')' if gov.annual_report_year else ''}",
                self.styles['Body']
            ))
            elements.append(Paragraph(
                f"<b>Aantal keer dat cyber/security/risk wordt genoemd:</b> {gov.cyber_mentions_in_report}",
                self.styles['BodySmall']
            ))
        else:
            elements.append(Paragraph(
                "<b>Jaarverslag gevonden:</b> Nee",
                self.styles['Body']
            ))

        # NIS2 implication
        elements.append(Spacer(1, 0.3*cm))
        elements.append(Paragraph(
            f'<font color="{Colors.WARNING.hexval()}"><b>NIS2 implicatie:</b></font> '
            f'NIS2 vereist bestuursaansprakelijkheid. Zonder zichtbare security governance '
            f'is onduidelijk wie verantwoordelijk is voor cybersecuritybeleid en incidentrespons.',
            self.styles['Body']
        ))

        return elements

    def _appendix_techstack(self, lead: LeadScore) -> List:
        """Tech Stack detail block."""
        elements = []
        ts = lead.techstack_result

        if not ts:
            elements.append(Paragraph("<i>Tech-stack-scan niet beschikbaar.</i>", self.styles['BodySmall']))
            return elements

        # Detected technologies table
        all_tech = (ts.technologies or []) + (ts.outdated_software or [])
        if all_tech:
            tech_data = [["Software", "Versie", "Status", "Risico"]]
            seen = set()
            for tech in all_tech:
                if isinstance(tech, dict):
                    name = tech.get('name', tech.get('software', str(tech)))
                    version = tech.get('version', tech.get('detected_version', ''))
                    status = tech.get('status', '')
                    risk = tech.get('risk', tech.get('description', ''))
                    # Mark outdated
                    if not status and tech in (ts.outdated_software or []):
                        status = "Verouderd"
                        risk = risk or "Bekende kwetsbaarheden mogelijk"
                else:
                    name = str(tech)
                    version = ""
                    status = ""
                    risk = ""
                key = f"{name}:{version}"
                if key not in seen:
                    seen.add(key)
                    tech_data.append([name, version or "—", status or "Actueel", risk or "—"])

            if len(tech_data) > 1:
                tech_table = Table(tech_data, colWidths=[4*cm, 3*cm, 3*cm, 4*cm])
                style = self._detail_table_style(len(tech_data))
                # Color outdated rows
                for i, tech in enumerate(all_tech, 1):
                    if i < len(tech_data) and isinstance(tech, dict):
                        if tech in (ts.outdated_software or []) or "verouderd" in str(tech.get('status', '')).lower() or "end-of-life" in str(tech.get('status', '')).lower():
                            style.add('TEXTCOLOR', (2, i), (2, i), Colors.DANGER)
                            style.add('FONTNAME', (2, i), (2, i), 'Helvetica-Bold')
                tech_table.setStyle(style)
                elements.append(Paragraph("<b>Gedetecteerde software:</b>", self.styles['Body']))
                elements.append(tech_table)

        # Version leaks
        if ts.version_leaks:
            elements.append(Spacer(1, 0.3*cm))
            elements.append(Paragraph("<b>Server headers die versie-informatie lekken:</b>", self.styles['Body']))
            for leak in ts.version_leaks:
                if isinstance(leak, dict):
                    header = leak.get('header', leak.get('name', ''))
                    value = leak.get('value', leak.get('version', ''))
                    elements.append(Paragraph(
                        f'\u2022 <font color="{Colors.WARNING.hexval()}">{header}</font>: {value}',
                        self.styles['BodySmall']
                    ))
                else:
                    elements.append(Paragraph(f"\u2022 {leak}", self.styles['BodySmall']))

        # Server info
        if ts.server_info:
            elements.append(Spacer(1, 0.2*cm))
            elements.append(Paragraph(
                f'<b>Server header:</b> <font color="{Colors.WARNING.hexval()}">{ts.server_info}</font>',
                self.styles['Body']
            ))

        # CMS
        if ts.cms_detected:
            elements.append(Paragraph(f"<b>CMS gedetecteerd:</b> {ts.cms_detected}", self.styles['Body']))

        return elements

    # ------------------------------------------------------------------
    # Shared helpers for appendix
    # ------------------------------------------------------------------

    def _detail_table_style(self, row_count: int) -> TableStyle:
        """Return a reusable table style for appendix detail tables."""
        return TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 0), (-1, 0), Colors.SECONDARY),
            ('TEXTCOLOR', (0, 0), (-1, 0), Colors.WHITE),
            ('GRID', (0, 0), (-1, -1), 0.5, Colors.TEXT_LIGHT),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [Colors.WHITE, colors.HexColor('#f7fafc')]),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ])

    @staticmethod
    def _port_service_name(port: int) -> str:
        """Map common ports to service names."""
        common = {
            80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 23: "Telnet",
            25: "SMTP", 53: "DNS", 110: "POP3", 143: "IMAP", 993: "IMAPS",
            995: "POP3S", 3306: "MySQL", 5432: "PostgreSQL", 3389: "RDP",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 445: "SMB", 135: "MSRPC",
            139: "NetBIOS", 1433: "MSSQL", 1521: "Oracle", 5900: "VNC",
            6379: "Redis", 27017: "MongoDB",
        }
        return common.get(port, f"Poort {port}")
    
    # Helper methods for extracting findings
    def _get_email_findings(self, lead: LeadScore) -> List[str]:
        """Extract email security findings."""
        findings = []
        if lead.dns_result:
            if not lead.dns_result.has_spf:
                findings.append("No SPF record configured - vulnerable to email spoofing")
            elif lead.dns_result.spf_record and "~all" in lead.dns_result.spf_record:
                findings.append("SPF uses soft fail (~all) instead of hard fail (-all)")
            
            if not lead.dns_result.has_dmarc:
                findings.append("No DMARC policy configured - no email authentication enforcement")
            elif lead.dns_result.dmarc_record and "p=none" in lead.dns_result.dmarc_record:
                findings.append("DMARC policy is 'none' - monitoring only, no enforcement")
            
            if not lead.dns_result.has_dkim:
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
                    findings.append(f"SSL certificate expires in {lead.ssl_result.days_until_expiry} days")
            
            if lead.ssl_result.protocol_version and "TLS 1.0" in lead.ssl_result.protocol_version:
                findings.append("Deprecated TLS 1.0 protocol in use")
            elif lead.ssl_result.protocol_version and "TLS 1.1" in lead.ssl_result.protocol_version:
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
                findings.append("No cookie consent mechanism detected - potential GDPR issue")
            if lead.cookie_result.tracking_cookies:
                findings.append(f"{len(lead.cookie_result.tracking_cookies)} tracking cookies detected")
            if lead.cookie_result.cookies_before_consent:
                findings.append(f"{len(lead.cookie_result.cookies_before_consent)} cookies set before consent")
        else:
            findings.append("Cookie scan not completed")
        
        return findings
    
    def _get_subdomain_findings(self, lead: LeadScore) -> List[str]:
        """Extract subdomain/attack surface findings."""
        findings = []
        if lead.subdomain_result:
            count = len(lead.subdomain_result.subdomains_found) if lead.subdomain_result.subdomains_found else 0
            findings.append(f"Discovered {count} subdomains via certificate transparency")
            
            if lead.subdomain_result.risky_subdomains:
                findings.append(f"Found {len(lead.subdomain_result.risky_subdomains)} potentially risky subdomains")
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
    
    def _get_score_color(self, score: int):
        """Get color for individual score."""
        if score == 0:
            return Colors.DANGER
        elif score == 1:
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
    safe_name = "".join(c for c in lead.company_name if c.isalnum() or c in (' ', '-', '_')).strip()
    safe_name = safe_name.replace(' ', '_')
    
    output_path = Path(output_dir) / f"security_report_{safe_name}_{datetime.now().strftime('%Y%m%d')}.pdf"
    
    return generator.generate(lead, str(output_path))
