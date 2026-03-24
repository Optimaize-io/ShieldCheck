"""
Lead Scoring Engine
Aggregates scan results into a comprehensive lead score.

KEY INSIGHT: Lower score = hotter lead. Companies with poor security NEED Nomios the most.
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum

from scanners.dns_scanner import DNSScanResult
from scanners.shodan_scanner import ShodanScanResult
from scanners.ssl_scanner import SSLScanResult
from scanners.website_scanner import WebsiteScanResult
from scanners.jobs_scanner import JobsScanResult
from scanners.governance_scanner import GovernanceScanResult
from scanners.admin_scanner import AdminScanResult
from scanners.headers_scanner import HeadersScanResult
from scanners.cookie_scanner import CookieScanResult
from scanners.subdomain_scanner import SubdomainScanResult
from scanners.techstack_scanner import TechStackScanResult
from .nis2_sectors import NIS2Sectors, NIS2SectorInfo


class LeadTier(Enum):
    """Lead classification tiers."""
    HOT = "🔴 HOT"      # Score 0-6: Major gaps, highest priority
    WARM = "🟠 WARM"    # Score 7-12: Notable gaps, good opportunity
    COOL = "🟢 COOL"    # Score 13-18: Reasonably prepared, low priority


@dataclass
class ScoreDimension:
    """Individual scoring dimension result."""
    name: str
    score: int  # 0-2
    max_score: int = 2
    emoji: str = ""
    description: str = ""
    
    def __post_init__(self):
        """Set emoji based on score."""
        if self.score == 0:
            self.emoji = "🔴"
        elif self.score == 1:
            self.emoji = "🟡"
        else:
            self.emoji = "🟢"


@dataclass
class LeadScore:
    """Complete lead scoring result for a company."""
    company_name: str
    domain: str
    sector: str
    employees: int
    
    # Individual dimension scores (12 dimensions, 0-2 each = 0-24 total)
    email_security: Optional[ScoreDimension] = None
    technical_hygiene: Optional[ScoreDimension] = None
    tls_certificate: Optional[ScoreDimension] = None
    http_headers: Optional[ScoreDimension] = None
    cookie_compliance: Optional[ScoreDimension] = None
    attack_surface: Optional[ScoreDimension] = None
    tech_stack: Optional[ScoreDimension] = None
    admin_panel: Optional[ScoreDimension] = None
    security_hiring: Optional[ScoreDimension] = None
    security_governance: Optional[ScoreDimension] = None
    security_communication: Optional[ScoreDimension] = None
    nis2_readiness: Optional[ScoreDimension] = None
    
    # Aggregate
    total_score: float = 0.0
    max_score: float = 24.0  # 12 dimensions x 2 points each
    findings_count: int = 0  # Total number of findings
    tier: LeadTier = LeadTier.WARM
    
    # NIS2 classification
    nis2_sector: Optional[str] = None
    nis2_entity_type: Optional[str] = None
    nis2_covered: bool = False
    compliance_priority: str = "UNKNOWN"
    
    # Key findings for sales
    key_gaps: List[str] = field(default_factory=list)
    sales_angles: List[str] = field(default_factory=list)
    
    # Extended report fields
    key_gaps_detailed: List[Dict[str, str]] = field(default_factory=list)
    management_summary: str = ""
    positive_findings: List[str] = field(default_factory=list)
    
    # Raw scan results
    dns_result: Optional[DNSScanResult] = None
    shodan_result: Optional[ShodanScanResult] = None
    ssl_result: Optional[SSLScanResult] = None
    website_result: Optional[WebsiteScanResult] = None
    jobs_result: Optional[JobsScanResult] = None
    governance_result: Optional[GovernanceScanResult] = None
    admin_result: Optional[AdminScanResult] = None
    headers_result: Optional[HeadersScanResult] = None
    cookie_result: Optional[CookieScanResult] = None
    subdomain_result: Optional[SubdomainScanResult] = None
    techstack_result: Optional[TechStackScanResult] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "company_name": self.company_name,
            "domain": self.domain,
            "sector": self.sector,
            "employees": self.employees,
            "scores": {
                "email_security": {
                    "score": self.email_security.score if self.email_security else 0,
                    "description": self.email_security.description if self.email_security else ""
                },
                "technical_hygiene": {
                    "score": self.technical_hygiene.score if self.technical_hygiene else 0,
                    "description": self.technical_hygiene.description if self.technical_hygiene else ""
                },
                "tls_certificate": {
                    "score": self.tls_certificate.score if self.tls_certificate else 0,
                    "description": self.tls_certificate.description if self.tls_certificate else ""
                },
                "http_headers": {
                    "score": self.http_headers.score if self.http_headers else 0,
                    "description": self.http_headers.description if self.http_headers else ""
                },
                "cookie_compliance": {
                    "score": self.cookie_compliance.score if self.cookie_compliance else 0,
                    "description": self.cookie_compliance.description if self.cookie_compliance else ""
                },
                "attack_surface": {
                    "score": self.attack_surface.score if self.attack_surface else 0,
                    "description": self.attack_surface.description if self.attack_surface else ""
                },
                "tech_stack": {
                    "score": self.tech_stack.score if self.tech_stack else 0,
                    "description": self.tech_stack.description if self.tech_stack else ""
                },
                "admin_panel": {
                    "score": self.admin_panel.score if self.admin_panel else 0,
                    "description": self.admin_panel.description if self.admin_panel else ""
                },
                "security_hiring": {
                    "score": self.security_hiring.score if self.security_hiring else 0,
                    "description": self.security_hiring.description if self.security_hiring else ""
                },
                "security_governance": {
                    "score": self.security_governance.score if self.security_governance else 0,
                    "description": self.security_governance.description if self.security_governance else ""
                },
                "security_communication": {
                    "score": self.security_communication.score if self.security_communication else 0,
                    "description": self.security_communication.description if self.security_communication else ""
                },
                "nis2_readiness": {
                    "score": self.nis2_readiness.score if self.nis2_readiness else 0,
                    "description": self.nis2_readiness.description if self.nis2_readiness else ""
                },
            },
            "total_score": self.total_score,
            "max_score": self.max_score,
            "findings_count": self.findings_count,
            "tier": self.tier.value,
            "nis2": {
                "sector": self.nis2_sector,
                "entity_type": self.nis2_entity_type,
                "covered": self.nis2_covered,
                "compliance_priority": self.compliance_priority
            },
            "key_gaps": self.key_gaps,
            "key_gaps_detailed": self.key_gaps_detailed,
            "management_summary": self.management_summary,
            "positive_findings": self.positive_findings,
            "sales_angles": self.sales_angles,
            "raw_results": {
                "dns": self.dns_result.to_dict() if self.dns_result else None,
                "shodan": self.shodan_result.to_dict() if self.shodan_result else None,
                "ssl": self.ssl_result.to_dict() if self.ssl_result else None,
                "website": self.website_result.to_dict() if self.website_result else None,
                "jobs": self.jobs_result.to_dict() if self.jobs_result else None,
                "governance": self.governance_result.to_dict() if self.governance_result else None,
                "admin": self.admin_result.to_dict() if self.admin_result else None,
                "headers": self.headers_result.to_dict() if self.headers_result else None,
                "cookies": self.cookie_result.to_dict() if self.cookie_result else None,
                "subdomains": self.subdomain_result.to_dict() if self.subdomain_result else None,
                "techstack": self.techstack_result.to_dict() if self.techstack_result else None
            }
        }


class LeadScorer:
    """
    Aggregates scan results into a comprehensive lead score.
    
    Scoring dimensions (each 0-2, total 0-18):
    1. Email Security - SPF, DMARC, DKIM
    2. Technical Hygiene - Shodan exposure, CVEs, risky ports
    3. TLS Certificate - Validity, expiry, protocol
    4. HTTP Security Headers - Security headers grade A-F
    5. Cookie Compliance - GDPR cookie consent
    6. Attack Surface - Risky subdomains via crt.sh
    7. Tech Stack Hygiene - Outdated software detection
    8. Security Communication - Website content about security
    9. NIS2 Readiness - Explicit NIS2/compliance mentions
    
    Tiers:
    - HOT: 0-6 (major gaps)
    - WARM: 7-12 (notable gaps)
    - COOL: 13-18 (well prepared)
    """
    
    def __init__(self):
        self.nis2_sectors = NIS2Sectors()
    
    def score(
        self,
        company_name: str,
        domain: str,
        sector: str,
        employees: int,
        dns_result: Optional[DNSScanResult] = None,
        shodan_result: Optional[ShodanScanResult] = None,
        ssl_result: Optional[SSLScanResult] = None,
        website_result: Optional[WebsiteScanResult] = None,
        jobs_result: Optional[JobsScanResult] = None,
        governance_result: Optional[GovernanceScanResult] = None,
        admin_result: Optional[AdminScanResult] = None,
        headers_result: Optional[HeadersScanResult] = None,
        cookie_result: Optional[CookieScanResult] = None,
        subdomain_result: Optional[SubdomainScanResult] = None,
        techstack_result: Optional[TechStackScanResult] = None
    ) -> LeadScore:
        """
        Calculate comprehensive lead score from scan results.
        
        Args:
            company_name: Company name
            domain: Domain scanned
            sector: Stated sector/industry
            employees: Estimated employee count
            dns_result: DNS scan results
            shodan_result: Shodan scan results
            ssl_result: SSL scan results
            website_result: Website scan results
            jobs_result: Jobs scan results
            governance_result: Governance scan results
            admin_result: Admin scan results
            headers_result: HTTP headers scan results
            cookie_result: Cookie compliance scan results
            subdomain_result: Subdomain discovery scan results
            techstack_result: Tech stack detection scan results
            
        Returns:
            Complete LeadScore with all analysis
        """
        lead = LeadScore(
            company_name=company_name,
            domain=domain,
            sector=sector,
            employees=employees,
            dns_result=dns_result,
            shodan_result=shodan_result,
            ssl_result=ssl_result,
            website_result=website_result,
            jobs_result=jobs_result,
            governance_result=governance_result,
            admin_result=admin_result,
            headers_result=headers_result,
            cookie_result=cookie_result,
            subdomain_result=subdomain_result,
            techstack_result=techstack_result
        )
        
        # Score each dimension (12 dimensions)
        lead.email_security = self._score_email_security(dns_result)
        lead.technical_hygiene = self._score_technical_hygiene(shodan_result)
        lead.tls_certificate = self._score_tls_certificate(ssl_result)
        lead.http_headers = self._score_http_headers(headers_result)
        lead.cookie_compliance = self._score_cookie_compliance(cookie_result)
        lead.attack_surface = self._score_attack_surface(subdomain_result)
        lead.tech_stack = self._score_tech_stack(techstack_result)
        lead.admin_panel = self._score_admin_exposure(admin_result)
        lead.security_hiring = self._score_security_hiring(jobs_result)
        lead.security_governance = self._score_security_leadership(governance_result)
        lead.security_communication = self._score_security_communication(website_result)
        lead.nis2_readiness = self._score_nis2_readiness(website_result)
        
        # Calculate total score (raw 0-24)
        dimension_scores = [
            lead.email_security.score if lead.email_security else 0,
            lead.technical_hygiene.score if lead.technical_hygiene else 0,
            lead.tls_certificate.score if lead.tls_certificate else 0,
            lead.http_headers.score if lead.http_headers else 0,
            lead.cookie_compliance.score if lead.cookie_compliance else 0,
            lead.attack_surface.score if lead.attack_surface else 0,
            lead.tech_stack.score if lead.tech_stack else 0,
            lead.admin_panel.score if lead.admin_panel else 0,
            lead.security_hiring.score if lead.security_hiring else 0,
            lead.security_governance.score if lead.security_governance else 0,
            lead.security_communication.score if lead.security_communication else 0,
            lead.nis2_readiness.score if lead.nis2_readiness else 0,
        ]
        lead.total_score = sum(dimension_scores)  # Raw 0-24 score
        lead.max_score = 24.0
        
        # Count total findings
        lead.findings_count = self._count_findings(lead)
        
        # Determine tier (based on 0-18 scale)
        lead.tier = self._determine_tier(lead.total_score)
        
        # NIS2 classification
        self._classify_nis2(lead, website_result)
        
        # Generate key gaps and sales angles
        lead.key_gaps = self._identify_key_gaps(lead)
        lead.sales_angles = self._generate_sales_angles(lead)
        
        # Generate extended report fields
        lead.key_gaps_detailed = self._generate_detailed_gaps(lead)
        lead.management_summary = self._generate_management_summary(lead)
        lead.positive_findings = self._generate_positive_findings(lead)
        
        return lead
    
    def _count_findings(self, lead: LeadScore) -> int:
        """Count total number of findings across all scanners."""
        count = 0
        
        # Count from each scanner's findings
        if lead.headers_result and lead.headers_result.headers_missing:
            count += len(lead.headers_result.headers_missing)
        if lead.headers_result and lead.headers_result.info_leakage:
            count += len(lead.headers_result.info_leakage)
        if lead.cookie_result and lead.cookie_result.tracking_cookies:
            count += len(lead.cookie_result.tracking_cookies)
        if lead.subdomain_result and lead.subdomain_result.risky_subdomains:
            count += len(lead.subdomain_result.risky_subdomains)
        if lead.techstack_result and lead.techstack_result.outdated_software:
            count += len(lead.techstack_result.outdated_software)
        if lead.techstack_result and lead.techstack_result.version_leaks:
            count += len(lead.techstack_result.version_leaks)
        if lead.shodan_result and lead.shodan_result.vulns:
            count += len(lead.shodan_result.vulns)
        if lead.shodan_result and lead.shodan_result.risky_ports:
            count += len(lead.shodan_result.risky_ports)
        if lead.admin_result:
            count += lead.admin_result.exposed_without_mfa
        if lead.dns_result:
            if lead.dns_result.spf_score == 0:
                count += 1
            if lead.dns_result.dmarc_score == 0:
                count += 1
        if lead.ssl_result and lead.ssl_result.score == 0:
            count += 1
        
        return count
    
    def _score_email_security(self, dns_result: Optional[DNSScanResult]) -> ScoreDimension:
        """Score email security from DNS results."""
        if not dns_result:
            return ScoreDimension(
                name="Email Security",
                score=0,
                description="Could not check email security"
            )
        
        # Average of SPF, DMARC, DKIM (each 0-2)
        avg = (dns_result.spf_score + dns_result.dmarc_score + dns_result.dkim_score) / 3
        score = round(avg)
        
        if score == 0:
            desc = "Poor email protection"
        elif score == 1:
            desc = "Partial email protection"
        else:
            desc = "Strong email protection"
        
        return ScoreDimension(
            name="Email Security",
            score=score,
            description=desc
        )
    
    def _score_technical_hygiene(self, shodan_result: Optional[ShodanScanResult]) -> ScoreDimension:
        """Score technical hygiene from Shodan results."""
        if not shodan_result:
            return ScoreDimension(
                name="Technical Hygiene",
                score=2,  # Assume good if we can't check
                description="Could not verify (assumed good)"
            )
        
        score = shodan_result.score
        
        if score == 0:
            desc = f"Critical issues: {len(shodan_result.vulns)} CVEs, {len(shodan_result.risky_ports)} risky ports"
        elif score == 1:
            desc = "Some exposure concerns"
        else:
            if shodan_result.not_indexed:
                desc = "Low internet exposure"
            else:
                desc = "Clean internet profile"
        
        return ScoreDimension(
            name="Technical Hygiene",
            score=score,
            description=desc
        )
    
    def _score_tls_certificate(self, ssl_result: Optional[SSLScanResult]) -> ScoreDimension:
        """Score TLS certificate from SSL results."""
        if not ssl_result:
            return ScoreDimension(
                name="TLS Certificate",
                score=0,
                description="Could not verify SSL"
            )
        
        score = ssl_result.score
        
        if score == 0:
            if ssl_result.days_until_expiry is not None and ssl_result.days_until_expiry < 30:
                desc = f"Expires in {ssl_result.days_until_expiry} days"
            else:
                desc = "Invalid or missing certificate"
        elif score == 1:
            desc = f"Valid but expiring in {ssl_result.days_until_expiry} days"
        else:
            desc = f"Valid certificate ({ssl_result.protocol_version})"
        
        return ScoreDimension(
            name="TLS Certificate",
            score=score,
            description=desc
        )
    
    def _score_http_headers(self, headers_result: Optional[HeadersScanResult]) -> ScoreDimension:
        """Score HTTP security headers."""
        if not headers_result:
            return ScoreDimension(
                name="HTTP Headers",
                score=1,  # Neutral if we couldn't check
                description="Could not analyze headers"
            )
        
        score = headers_result.score
        grade = headers_result.grade
        
        if score == 0:
            desc = f"Grade {grade} - Poor security headers"
        elif score == 1:
            desc = f"Grade {grade} - Partial headers"
        else:
            desc = f"Grade {grade} - Good security headers"
        
        return ScoreDimension(
            name="HTTP Headers",
            score=score,
            description=desc
        )
    
    def _score_cookie_compliance(self, cookie_result: Optional[CookieScanResult]) -> ScoreDimension:
        """Score cookie/GDPR compliance."""
        if not cookie_result:
            return ScoreDimension(
                name="Cookie Compliance",
                score=1,  # Neutral if we couldn't check
                description="Could not analyze cookies"
            )
        
        score = cookie_result.score
        
        if score == 0:
            num_trackers = len(cookie_result.tracking_cookies)
            desc = f"Tracking without consent ({num_trackers} cookies)"
        elif score == 1:
            desc = "Banner present but cookies leak"
        else:
            desc = "GDPR compliant cookies"
        
        return ScoreDimension(
            name="Cookie Compliance",
            score=score,
            description=desc
        )
    
    def _score_attack_surface(self, subdomain_result: Optional[SubdomainScanResult]) -> ScoreDimension:
        """Score attack surface from subdomain discovery."""
        if not subdomain_result:
            return ScoreDimension(
                name="Attack Surface",
                score=1,  # Neutral if we couldn't check
                description="Could not check subdomains"
            )
        
        score = subdomain_result.score
        risky_count = len(subdomain_result.risky_subdomains)
        
        if score == 0:
            desc = f"{risky_count} risky subdomains exposed"
        elif score == 1:
            desc = f"{risky_count} potentially risky subdomains"
        else:
            if subdomain_result.total_count == 0:
                desc = "No subdomains found"
            else:
                desc = f"Clean attack surface ({subdomain_result.total_count} subdomains)"
        
        return ScoreDimension(
            name="Attack Surface",
            score=score,
            description=desc
        )
    
    def _score_tech_stack(self, techstack_result: Optional[TechStackScanResult]) -> ScoreDimension:
        """Score tech stack hygiene."""
        if not techstack_result:
            return ScoreDimension(
                name="Tech Stack",
                score=1,  # Neutral if we couldn't check
                description="Could not analyze tech stack"
            )
        
        score = techstack_result.score
        
        if score == 0:
            num_outdated = len(techstack_result.outdated_software)
            desc = f"Outdated software ({num_outdated} issues)"
        elif score == 1:
            if techstack_result.version_leaks:
                desc = "Version info leaked"
            else:
                desc = "Minor tech hygiene issues"
        else:
            if techstack_result.cms_detected:
                desc = f"Modern stack ({techstack_result.cms_detected})"
            else:
                desc = "Clean tech stack"
        
        return ScoreDimension(
            name="Tech Stack",
            score=score,
            description=desc
        )
    
    def _score_security_communication(self, website_result: Optional[WebsiteScanResult]) -> ScoreDimension:
        """Score security communication from website results."""
        if not website_result:
            return ScoreDimension(
                name="Security Communication",
                score=0,
                description="Could not analyze website"
            )
        
        score = website_result.security_communication_score
        
        if score == 0:
            desc = "Minimal security messaging"
        elif score == 1:
            desc = "Some security awareness"
        else:
            if website_result.has_security_page:
                desc = "Dedicated security page"
            else:
                desc = "Strong security messaging"
        
        return ScoreDimension(
            name="Security Communication",
            score=score,
            description=desc
        )
    
    def _score_nis2_readiness(self, website_result: Optional[WebsiteScanResult]) -> ScoreDimension:
        """Score NIS2 readiness from website results."""
        if not website_result:
            return ScoreDimension(
                name="NIS2 Readiness",
                score=0,
                description="Could not analyze website"
            )
        
        score = website_result.nis2_readiness_score
        
        if score == 0:
            desc = "No NIS2/compliance mentioned"
        elif score == 1:
            desc = "ISO 27001 mentioned, no NIS2"
        else:
            desc = "NIS2 explicitly mentioned"
        
        return ScoreDimension(
            name="NIS2 Readiness",
            score=score,
            description=desc
        )
    
    def _score_security_hiring(self, jobs_result: Optional[JobsScanResult]) -> ScoreDimension:
        """Score security hiring activity from jobs scan."""
        if not jobs_result:
            return ScoreDimension(
                name="Security Hiring",
                score=1,  # Neutral if we couldn't check
                description="Could not analyze job postings"
            )
        
        score = jobs_result.score
        
        if score == 0:
            desc = "No jobs page found"
        elif score == 1:
            desc = "Jobs page but no security roles"
        else:
            count = jobs_result.security_jobs_found
            desc = f"Hiring security staff ({count} role{'s' if count > 1 else ''})"
        
        return ScoreDimension(
            name="Security Hiring",
            score=score,
            description=desc
        )
    
    def _score_security_leadership(self, governance_result: Optional[GovernanceScanResult]) -> ScoreDimension:
        """Score security leadership from governance scan."""
        if not governance_result:
            return ScoreDimension(
                name="Security Leadership",
                score=1,  # Neutral if we couldn't check
                description="Could not analyze governance"
            )
        
        # Combine leadership and report scores
        leadership_score = governance_result.leadership_score
        report_score = governance_result.report_score
        combined = round((leadership_score + report_score) / 2)
        
        if combined == 0:
            if governance_result.leadership_score == 0:
                desc = "No CISO/security officer visible"
            else:
                desc = "Limited security governance visible"
        elif combined == 1:
            parts = []
            if governance_result.security_roles_found:
                parts.append(f"{len(governance_result.security_roles_found)} security role(s)")
            if governance_result.annual_reports_found:
                parts.append("annual report")
            desc = "Partial: " + ", ".join(parts) if parts else "Some governance indicators"
        else:
            desc = "Strong security governance visible"
        
        return ScoreDimension(
            name="Security Leadership",
            score=combined,
            description=desc
        )
    
    def _score_admin_exposure(self, admin_result: Optional[AdminScanResult]) -> ScoreDimension:
        """Score admin exposure from admin scan."""
        if not admin_result:
            return ScoreDimension(
                name="Admin Exposure",
                score=1,  # Neutral if we couldn't check  
                description="Could not analyze admin exposure"
            )
        
        score = admin_result.score
        
        total_found = len(admin_result.admin_pages_found) + len(admin_result.login_pages_found)
        
        if score == 0:
            desc = f"{total_found} admin page(s) without MFA"
        elif score == 1:
            if admin_result.mfa_indicators:
                desc = f"Admin pages with partial MFA ({', '.join(admin_result.mfa_indicators[:2])})"
            else:  
                desc = "Some admin pages detected"
        else:
            if admin_result.sso_providers_detected:
                desc = f"Protected with {', '.join(admin_result.sso_providers_detected[:2])}"
            elif total_found == 0:
                desc = "No exposed admin pages"
            else:
                desc = "Admin pages properly secured"
        
        return ScoreDimension(
            name="Admin Exposure",
            score=score,
            description=desc
        )
    
    def _determine_tier(self, total_score: float) -> LeadTier:
        """Determine lead tier from total score (0-24 scale)."""
        if total_score <= 8:
            return LeadTier.HOT
        elif total_score <= 14:
            return LeadTier.WARM
        else:
            return LeadTier.COOL
    
    def _classify_nis2(self, lead: LeadScore, website_result: Optional[WebsiteScanResult]) -> None:
        """Classify company under NIS2."""
        # Try sector name first
        sector_info = self.nis2_sectors.classify_by_sector_name(lead.sector)
        
        # If not found and we have website results, try those
        if not sector_info and website_result and website_result.sector_indicators:
            matches = self.nis2_sectors.classify_by_keywords(website_result.sector_indicators)
            if matches:
                sector_info = matches[0]  # Take first match
        
        if sector_info:
            lead.nis2_sector = sector_info.name_en
            lead.nis2_entity_type = sector_info.entity_type
            lead.nis2_covered = self.nis2_sectors.is_covered(
                sector_info.sector_id, lead.employees
            )
            lead.compliance_priority = self.nis2_sectors.get_compliance_priority(
                sector_info.sector_id, lead.employees
            )
        else:
            # Couldn't classify - might still be covered
            if lead.employees >= 250:
                lead.compliance_priority = "MEDIUM"  # Large companies often affected
    
    def _identify_key_gaps(self, lead: LeadScore) -> List[str]:
        """Identify key security gaps for sales messaging."""
        gaps = []
        
        # Email security gaps
        if lead.email_security and lead.email_security.score == 0:
            if lead.dns_result:
                if lead.dns_result.dmarc_score == 0:
                    gaps.append(f"No DMARC - email spoofing of @{lead.domain} possible")
                if lead.dns_result.spf_score == 0:
                    gaps.append("Missing SPF record")
        
        # Technical gaps
        if lead.technical_hygiene and lead.technical_hygiene.score == 0:
            if lead.shodan_result:
                if lead.shodan_result.vulns:
                    gaps.append(f"{len(lead.shodan_result.vulns)} known CVEs detected")
                for port, desc in lead.shodan_result.risky_ports_detail.items():
                    if port in {23, 3389, 5900, 445}:
                        gaps.append(f"Port {port} open: {desc.split(' - ')[0]}")
        
        # SSL gaps
        if lead.tls_certificate and lead.tls_certificate.score == 0:
            if lead.ssl_result and lead.ssl_result.days_until_expiry is not None:
                if lead.ssl_result.days_until_expiry < 0:
                    gaps.append("SSL certificate EXPIRED")
                elif lead.ssl_result.days_until_expiry < 30:
                    gaps.append(f"SSL expires in {lead.ssl_result.days_until_expiry} days")
        
        # HTTP Headers gaps
        if lead.http_headers and lead.http_headers.score == 0:
            if lead.headers_result:
                missing = lead.headers_result.headers_missing[:3]
                gaps.append(f"Missing security headers: {', '.join(missing)}")
        
        # Cookie compliance gaps
        if lead.cookie_compliance and lead.cookie_compliance.score == 0:
            if lead.cookie_result:
                gaps.append(f"GDPR violation: {len(lead.cookie_result.tracking_cookies)} tracking cookies without consent")
        
        # Attack surface gaps
        if lead.attack_surface and lead.attack_surface.score == 0:
            if lead.subdomain_result:
                risky = [s['subdomain'] for s in lead.subdomain_result.risky_subdomains[:3]]
                gaps.append(f"Risky subdomains exposed: {', '.join(risky)}")
        
        # Tech stack gaps
        if lead.tech_stack and lead.tech_stack.score == 0:
            if lead.techstack_result and lead.techstack_result.outdated_software:
                sw = lead.techstack_result.outdated_software[0]
                gaps.append(f"Outdated software: {sw['software']} {sw['version']}")
        
        # NIS2 gaps
        if lead.nis2_readiness and lead.nis2_readiness.score == 0:
            if lead.nis2_covered:
                gaps.append("NIS2 covered but no compliance mentioned")
        
        return gaps
    
    def _generate_sales_angles(self, lead: LeadScore) -> List[str]:
        """Generate specific sales approach recommendations."""
        angles = []
        
        # Email spoofing angle
        if lead.dns_result and lead.dns_result.dmarc_score == 0:
            angles.append(
                f"Lead with email security: anyone can spoof @{lead.domain} today. "
                "Demonstrate with a test phishing email mock-up."
            )
        
        # Critical vulnerabilities angle
        if lead.shodan_result and lead.shodan_result.vulns:
            num_vulns = len(lead.shodan_result.vulns)
            if num_vulns > 5:
                angles.append(
                    f"Open with vulnerability report: {num_vulns} known CVEs on internet-facing systems. "
                    "Urgency is high - these are actively exploited."
                )
        
        # RDP/VNC angle
        if lead.shodan_result:
            for port in lead.shodan_result.risky_ports:
                if port == 3389:
                    angles.append(
                        "RDP port 3389 is open externally - this is a ransomware attack vector. "
                        "Start conversation with incident statistics."
                    )
                    break
                elif port == 5900:
                    angles.append(
                        "VNC port exposed - common attack vector. "
                        "Discuss remote access security."
                    )
                    break
        
        # Board liability angle (NIS2)
        if lead.nis2_covered and lead.nis2_readiness and lead.nis2_readiness.score == 0:
            if lead.employees >= 500:
                angles.append(
                    f"{lead.employees:,} employees in {lead.sector}, zero NIS2 mentions. "
                    "Board liability angle: directors are personally liable under Cyberbeveiligingswet."
                )
            else:
                angles.append(
                    f"NIS2-covered {lead.sector} company without visible compliance program. "
                    "Offer NIS2 readiness assessment."
                )
        
        # Supply chain angle
        if lead.sector and any(x in lead.sector.lower() for x in ['supplier', 'manufacturing', 'production', 'food']):
            angles.append(
                "Supply chain security: their customers will audit them under NIS2. "
                "Proactive compliance is a competitive advantage."
            )
        
        # Expiring SSL angle
        if lead.ssl_result and lead.ssl_result.days_until_expiry is not None:
            if 0 < lead.ssl_result.days_until_expiry < 30:
                angles.append(
                    f"Certificate expires in {lead.ssl_result.days_until_expiry} days - "
                    "offer to help with certificate management."
                )
        
        # GDPR/Cookie compliance angle
        if lead.cookie_result and lead.cookie_result.score == 0:
            trackers = len(lead.cookie_result.tracking_cookies)
            angles.append(
                f"GDPR violation: {trackers} tracking cookies without consent. "
                "Data privacy risk - offer compliance assessment."
            )
        
        # Security headers angle
        if lead.headers_result and lead.headers_result.score == 0:
            angles.append(
                f"Security headers grade {lead.headers_result.grade} - easy quick win. "
                "Offer hardening assessment and implementation."
            )
        
        # Risky subdomains angle  
        if lead.subdomain_result and lead.subdomain_result.risky_count >= 3:
            angles.append(
                f"{lead.subdomain_result.risky_count} risky subdomains exposed (staging, dev, admin). "
                "Attack surface reduction opportunity."
            )
        
        # Outdated tech stack angle
        if lead.techstack_result and lead.techstack_result.outdated_software:
            sw = lead.techstack_result.outdated_software[0]
            angles.append(
                f"Running outdated {sw['software']} - vulnerability remediation opportunity. "
                "Position as managed patching/upgrade service."
            )
        
        # Default angle if we have nothing specific
        if not angles:
            if lead.tier == LeadTier.HOT:
                angles.append(
                    "Multiple security gaps identified. Position as proactive security assessment "
                    "before they become incidents."
                )
            elif lead.tier == LeadTier.WARM:
                angles.append(
                    "Some gaps exist. Position as security maturity acceleration - "
                    "help them reach best practice faster."
                )
            else:
                angles.append(
                    "Already well-prepared. Position as continuous improvement partner "
                    "or second opinion on current security posture."
                )
        
        return angles

    def _generate_detailed_gaps(self, lead: LeadScore) -> List[Dict[str, str]]:
        """Generate detailed gap descriptions for the PDF report."""
        gaps = []

        # Email security
        if lead.email_security and lead.email_security.score == 0:
            finding_parts = []
            if lead.dns_result:
                if lead.dns_result.dmarc_score == 0:
                    finding_parts.append("No DMARC enforcement")
                if not lead.dns_result.dkim_found:
                    finding_parts.append("DKIM missing")
                if lead.dns_result.spf_score == 0:
                    finding_parts.append("No SPF record")
            gaps.append({
                "title": "E-mail spoofing mogelijk",
                "finding": ", ".join(finding_parts) if finding_parts else "Poor email protection",
                "description": (
                    f"Iedereen kan e-mails versturen die lijken te komen van @{lead.domain}. "
                    "DMARC is niet afgedwongen en DKIM is niet geconfigureerd, waardoor "
                    "er geen verificatie is van e-mail authenticiteit."
                ),
                "impact": (
                    "Phishing-aanvallen met het eigen domein van het bedrijf. Klanten en "
                    "medewerkers kunnen misleid worden door e-mails die echt lijken."
                ),
            })

        # Technical hygiene / CVEs
        if lead.technical_hygiene and lead.technical_hygiene.score == 0:
            vuln_count = len(lead.shodan_result.vulns) if lead.shodan_result and lead.shodan_result.vulns else 0
            sw_info = ""
            if lead.techstack_result and lead.techstack_result.version_leaks:
                sw_info = ", ".join(f"{v.get('header', '')} {v.get('value', '')}" for v in lead.techstack_result.version_leaks[:2])
            gaps.append({
                "title": f"{vuln_count} bekende kwetsbaarheden" if vuln_count else "Kritieke technische blootstelling",
                "finding": f"{sw_info} op publieke servers" if sw_info else lead.technical_hygiene.description,
                "description": (
                    f"De webserver draait op software met {vuln_count} publiekelijk bekende "
                    "kwetsbaarheden (CVEs). Sommige hiervan worden actief misbruikt door aanvallers."
                ) if vuln_count else (
                    "Er zijn risico's gedetecteerd op internet-gerichte systemen die "
                    "aanvallers kunnen misbruiken."
                ),
                "impact": (
                    "Aanvallers kunnen deze kwetsbaarheden gebruiken om toegang te krijgen tot "
                    "interne systemen, data te stelen, of ransomware te installeren."
                ),
            })

        # HTTP Headers
        if lead.http_headers and lead.http_headers.score == 0:
            grade = lead.headers_result.grade if lead.headers_result else "F"
            present = len(lead.headers_result.headers_present) if lead.headers_result and lead.headers_result.headers_present else 0
            gaps.append({
                "title": f"Security headers Grade {grade}",
                "finding": f"Grade {grade} — {present}/6 security headers aanwezig",
                "description": (
                    "De webserver mist essentiële security headers zoals Content-Security-Policy, "
                    "HSTS en X-Frame-Options. Dit maakt de website kwetsbaar voor veelvoorkomende aanvallen."
                ),
                "impact": (
                    "Cross-site scripting (XSS), clickjacking en andere browser-gebaseerde aanvallen "
                    "worden niet geblokkeerd door de server."
                ),
            })

        # NIS2 readiness
        if lead.nis2_readiness and lead.nis2_readiness.score == 0 and lead.nis2_covered:
            entity_type = lead.nis2_entity_type or "entity"
            gaps.append({
                "title": "Geen NIS2 compliance zichtbaar",
                "finding": f"NIS2 {entity_type} zonder zichtbaar compliance programma",
                "description": (
                    f"Als bedrijf in de sector {lead.sector} valt deze organisatie onder NIS2 als '{entity_type}'. "
                    "Er is nergens op de website of in publieke bronnen een compliance programma zichtbaar."
                ),
                "impact": (
                    "NIS2 vereist bestuursaansprakelijkheid voor cybersecurity. Boetes kunnen oplopen "
                    "tot €10 miljoen of 2% van de wereldwijde omzet."
                ),
            })

        # SSL/TLS
        if lead.tls_certificate and lead.tls_certificate.score == 0:
            gaps.append({
                "title": "TLS certificaat probleem",
                "finding": lead.tls_certificate.description,
                "description": (
                    "Het TLS certificaat is ongeldig, verlopen of ontbreekt. Dit betekent dat "
                    "bezoekers een beveiligingswaarschuwing zien en data niet versleuteld wordt."
                ),
                "impact": (
                    "Vertrouwelijke gegevens kunnen onderschept worden. Bezoekers verliezen "
                    "vertrouwen door browserwaarschuwingen."
                ),
            })

        # Cookie compliance
        if lead.cookie_compliance and lead.cookie_compliance.score == 0:
            gaps.append({
                "title": "GDPR cookie-overtreding",
                "finding": lead.cookie_compliance.description,
                "description": (
                    "Er worden tracking cookies geplaatst zonder expliciete toestemming van bezoekers. "
                    "Dit is een directe overtreding van de AVG/GDPR wetgeving."
                ),
                "impact": (
                    "Boetes tot 4% van de wereldwijde omzet, reputatieschade en verlies van "
                    "klantvertrouwen bij een AP-onderzoek."
                ),
            })

        # Security governance
        if lead.security_governance and lead.security_governance.score == 0:
            gaps.append({
                "title": "Geen security governance zichtbaar",
                "finding": lead.security_governance.description,
                "description": (
                    "Er is geen CISO, security officer of security leadership zichtbaar in het "
                    "management team. Dit suggereert dat cybersecurity geen bestuursverantwoordelijkheid is."
                ),
                "impact": (
                    "Zonder security governance is er geen strategische aansturing van cybersecurity. "
                    "Dit is onder NIS2 een vereiste voor bestuursaansprakelijkheid."
                ),
            })

        # Security hiring
        if lead.security_hiring and lead.security_hiring.score == 0:
            gaps.append({
                "title": "Geen security vacatures",
                "finding": lead.security_hiring.description,
                "description": (
                    "Er zijn geen security-gerelateerde vacatures gevonden. Dit kan betekenen dat "
                    "het bedrijf geen dedicated security team aan het opbouwen is."
                ),
                "impact": (
                    "Zonder dedicated security professionals is het lastig om een robuust "
                    "security programma op te zetten en te onderhouden."
                ),
            })

        # Attack surface
        if lead.attack_surface and lead.attack_surface.score == 0:
            risky_count = len(lead.subdomain_result.risky_subdomains) if lead.subdomain_result else 0
            gaps.append({
                "title": f"{risky_count} risicovolle subdomains",
                "finding": lead.attack_surface.description,
                "description": (
                    "Er zijn subdomains gevonden die wijzen op test-, staging- of admin-omgevingen "
                    "die publiekelijk bereikbaar zijn."
                ),
                "impact": (
                    "Aanvallers gebruiken deze subdomains om interne systemen te ontdekken "
                    "en kwetsbaarheden te vinden die niet bedoeld zijn voor publieke toegang."
                ),
            })

        return gaps[:5]  # Top 5 most critical

    def _generate_management_summary(self, lead: LeadScore) -> str:
        """Generate a plain-language management summary."""
        # Count red dimensions
        all_dims = self._get_all_dimensions(lead)
        red_count = sum(1 for _, dim in all_dims if dim and dim.score == 0)
        total_dims = len(all_dims)

        # Build top risks description
        top_risks = []
        if lead.email_security and lead.email_security.score == 0:
            top_risks.append(f"het ontbreken van e-mail authenticatie (waardoor het domein @{lead.domain} gespooft kan worden)")
        if lead.technical_hygiene and lead.technical_hygiene.score == 0:
            vuln_count = len(lead.shodan_result.vulns) if lead.shodan_result and lead.shodan_result.vulns else 0
            if vuln_count:
                top_risks.append(f"{vuln_count} bekende kwetsbaarheden op publieke servers")
            else:
                top_risks.append("kritieke technische blootstelling op publieke servers")
        if lead.nis2_readiness and lead.nis2_readiness.score == 0 and lead.nis2_covered:
            top_risks.append(f"het ontbreken van enig zichtbaar NIS2 compliance programma — terwijl het bedrijf als {lead.nis2_entity_type or 'entity'} onder NIS2 valt")
        if lead.http_headers and lead.http_headers.score == 0:
            top_risks.append("zeer zwakke security headers op de webserver")
        if lead.security_governance and lead.security_governance.score == 0:
            top_risks.append("geen zichtbaar security governance of CISO")

        risks_text = ""
        if len(top_risks) >= 3:
            risks_text = f"{', '.join(top_risks[:2])}, en {top_risks[2]}"
        elif len(top_risks) == 2:
            risks_text = f"{top_risks[0]} en {top_risks[1]}"
        elif top_risks:
            risks_text = top_risks[0]

        score_int = int(lead.total_score)
        max_int = int(lead.max_score)

        summary = (
            f"De externe security posture van {lead.company_name} scoort {score_int} van {max_int} punten "
            f"over {total_dims} dimensies, wat wijst op "
        )

        if lead.tier == LeadTier.HOT:
            summary += "significante beveiligingslekken die publiekelijk zichtbaar zijn. "
        elif lead.tier == LeadTier.WARM:
            summary += "meerdere verbeterpunten in de beveiligingsposture. "
        else:
            summary += "een redelijk volwassen beveiligingsposture met enkele aandachtspunten. "

        if risks_text:
            summary += f"De belangrijkste risico's zijn {risks_text}."

        return summary

    def _generate_positive_findings(self, lead: LeadScore) -> List[str]:
        """Generate list of positive security findings for balance."""
        positives = []

        if lead.tls_certificate and lead.tls_certificate.score == 2:
            proto = ""
            if lead.ssl_result and lead.ssl_result.protocol_version:
                proto = f" en gebruikt modern {lead.ssl_result.protocol_version} protocol"
            positives.append(f"TLS certificaat is geldig{proto}")

        if lead.cookie_compliance and lead.cookie_compliance.score == 2:
            positives.append("Cookie configuratie is GDPR-compliant — geen tracking voor consent")

        if lead.admin_panel and lead.admin_panel.score == 2:
            positives.append("Geen admin panels publiekelijk toegankelijk")

        if lead.attack_surface and lead.attack_surface.score == 2:
            positives.append("Schoon aanvalsoppervlak — geen risicovolle subdomains gevonden")

        if lead.email_security and lead.email_security.score == 2:
            positives.append("E-mail authenticatie volledig geconfigureerd (SPF + DMARC + DKIM)")

        if lead.http_headers and lead.http_headers.score == 2:
            positives.append("Sterke security headers geconfigureerd op de webserver")

        if lead.tech_stack and lead.tech_stack.score == 2:
            positives.append("Moderne tech stack zonder verouderde software gedetecteerd")

        if lead.security_governance and lead.security_governance.score == 2:
            positives.append("Security governance en leadership zichtbaar in het management")

        if lead.security_hiring and lead.security_hiring.score == 2:
            positives.append("Actief bezig met het aannemen van security professionals")

        if lead.nis2_readiness and lead.nis2_readiness.score == 2:
            positives.append("NIS2 compliance expliciet benoemd op de website")

        if lead.security_communication and lead.security_communication.score == 2:
            positives.append("Dedicated security pagina aanwezig op de website")

        # Also include score=1 items if we don't have enough positives
        if len(positives) < 2:
            if lead.attack_surface and lead.attack_surface.score == 1:
                positives.append("Beperkte subdomain blootstelling")
            if lead.tech_stack and lead.tech_stack.score == 1:
                positives.append("Tech stack grotendeels up-to-date")
            if lead.tls_certificate and lead.tls_certificate.score == 1:
                positives.append("TLS certificaat aanwezig maar verloopt binnenkort")

        return positives

    def _get_all_dimensions(self, lead: LeadScore) -> List[tuple]:
        """Return all 12 scoring dimensions as (name, ScoreDimension) tuples."""
        return [
            ("Email Security", lead.email_security),
            ("Technical Hygiene", lead.technical_hygiene),
            ("TLS Certificate", lead.tls_certificate),
            ("HTTP Headers", lead.http_headers),
            ("Cookie Compliance", lead.cookie_compliance),
            ("Attack Surface", lead.attack_surface),
            ("Tech Stack", lead.tech_stack),
            ("Admin Panel", lead.admin_panel),
            ("Security Hiring", lead.security_hiring),
            ("Security Governance", lead.security_governance),
            ("Security Communication", lead.security_communication),
            ("NIS2 Readiness", lead.nis2_readiness),
        ]
