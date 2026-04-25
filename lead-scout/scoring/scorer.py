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
    analyzed: bool = True
    status: str = ""  # risk | warning | ok | unknown
    description: str = ""
    present: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    risks: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Set emoji based on score."""
        if not self.analyzed:
            self.status = "unknown"
            self.emoji = "?"
            return

        pct = (self.score / self.max_score) if self.max_score else 0.0
        if pct <= 0.33:
            self.status = "risk"
            self.emoji = "ðŸ”´"
        elif pct <= 0.66:
            self.status = "warning"
            self.emoji = "ðŸŸ¡"
        else:
            self.status = "ok"
            self.emoji = "ðŸŸ¢"
        return

        self.status = (
            "risk" if self.score == 0 else "warning" if self.score == 1 else "ok"
        )
        if self.score == 0:
            self.emoji = "🔴"
        elif self.score == 1:
            self.emoji = "🟡"
        else:
            self.emoji = "🟢"
    def score_for_total(self, neutral: int = 1) -> int:
        """Score contribution used in totals; unknown dimensions are neutral by default."""
        if not self.analyzed:
            return 0
        return int(self.score)

    def display_score(self) -> str:
        """Human-friendly score display."""
        if not self.analyzed:
            return "N/A"
        return f"{self.score}/{self.max_score}"


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
        def dim_to_dict(dim: Optional[ScoreDimension]) -> Dict[str, Any]:
            if not dim:
                return {
                    "score": None,
                    "max_score": None,
                    "analyzed": False,
                    "status": "unknown",
                    "description": "",
                    "present": [],
                    "missing": [],
                    "risks": [],
                }
            return {
                "score": dim.score if dim.analyzed else None,
                "max_score": dim.max_score if dim.analyzed else None,
                "analyzed": dim.analyzed,
                "status": dim.status,
                "description": dim.description,
                "present": list(dim.present),
                "missing": list(dim.missing),
                "risks": list(dim.risks),
            }

        return {
            "company_name": self.company_name,
            "domain": self.domain,
            "sector": self.sector,
            "employees": self.employees,
            "scores": {
                "email_security": dim_to_dict(self.email_security),
                "technical_hygiene": dim_to_dict(self.technical_hygiene),
                "tls_certificate": dim_to_dict(self.tls_certificate),
                "http_headers": dim_to_dict(self.http_headers),
                "cookie_compliance": dim_to_dict(self.cookie_compliance),
                "attack_surface": dim_to_dict(self.attack_surface),
                "tech_stack": dim_to_dict(self.tech_stack),
                "admin_panel": dim_to_dict(self.admin_panel),
                "security_hiring": dim_to_dict(self.security_hiring),
                "security_governance": dim_to_dict(self.security_governance),
                "security_communication": dim_to_dict(self.security_communication),
                "nis2_readiness": dim_to_dict(self.nis2_readiness),
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
    
    Scoring dimensions (each 0-2, total 0-24):
    1. Email Security - SPF, DMARC, DKIM
    2. Technical Hygiene - Shodan exposure, CVEs, risky ports
    3. TLS Certificate - Validity, expiry, protocol
    4. HTTP Security Headers - Security headers grade A-F
    5. Cookie Compliance - GDPR cookie consent
    6. Attack Surface - Risky subdomains via crt.sh
    7. Tech Stack Hygiene - Outdated software detection
    8. Admin Exposure - Admin/login exposure & MFA signals
    9. Security Hiring - Security job postings signal maturity
    10. Security Governance - Board/CISO/annual report signals
    11. Security Communication - Website content about security
    12. NIS2 Readiness - Explicit NIS2/compliance mentions
    
    Tiers:
    - HOT: 0-8 (major gaps)
    - WARM: 9-16 (notable gaps)
    - COOL: 17-24 (reasonably prepared)
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
        dimensions = [
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
            lead.nis2_readiness,
        ]
        analyzed_dimensions = [d for d in dimensions if d and d.analyzed]
        lead.total_score = float(sum(d.score for d in analyzed_dimensions))
        lead.max_score = float(sum(d.max_score for d in analyzed_dimensions))
        
        # Count total findings
        lead.findings_count = self._count_findings(lead)
        
        # Determine tier (based on 0-24 scale)
        lead.tier = self._determine_tier(lead.total_score, lead.max_score)
        
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
                score=1,
                analyzed=False,
                description="Not analyzed (DNS scan failed or timed out)"
            )
        
        max_score = 3
        score = 0
        present: List[str] = []
        missing: List[str] = []
        risks: List[str] = []

        if dns_result.spf_score == 2:
            score += 1
            present.append("SPF policy present and strict")
        else:
            missing.append("SPF missing or weak")
            risks.append("Without SPF, spoofed email from the domain is harder to block by recipients.")

        if dns_result.dmarc_score == 2:
            score += 1
            present.append("DMARC enforcement enabled (reject/quarantine)")
        else:
            missing.append("DMARC missing or not enforced")
            risks.append("Without DMARC enforcement, attackers can more easily impersonate the domain in phishing.")

        if dns_result.dkim_score == 2:
            score += 1
            present.append("DKIM signing configured")
        else:
            missing.append("DKIM missing or incomplete")
            risks.append("Without DKIM, recipients cannot verify that outbound mail was not tampered with.")

        desc = f"{score}/{max_score} email authentication controls at best-practice level"

        return ScoreDimension(
            name="Email Security",
            score=score,
            max_score=max_score,
            description=desc,
            present=present,
            missing=missing,
            risks=risks,
        )
    
    def _score_technical_hygiene(self, shodan_result: Optional[ShodanScanResult]) -> ScoreDimension:
        """Score technical hygiene from Shodan results."""
        if not shodan_result:
            return ScoreDimension(
                name="Technical Hygiene",
                score=1,
                analyzed=False,
                description="Not analyzed (Shodan scan failed or timed out)"
            )

        max_score = 3
        score = 0
        present: List[str] = []
        missing: List[str] = []
        risks: List[str] = []

        # 1) Vulnerabilities
        if not shodan_result.vulns:
            score += 1
            present.append("No known CVEs visible via Shodan InternetDB")
        else:
            missing.append(f"{len(shodan_result.vulns)} known vulnerability identifier(s) exposed")
            risks.append("Known vulnerabilities on internet-facing systems increase breach likelihood and urgency.")

        # 2) High-risk ports
        high_risk_ports = {21, 23, 445, 3389, 5900, 27017, 6379}
        high_risk_found = [p for p in (shodan_result.risky_ports or []) if p in high_risk_ports]
        if not high_risk_found:
            score += 1
            present.append("No high-risk ports detected (e.g., RDP/SMB/Telnet)")
        else:
            shown = ", ".join(str(p) for p in sorted(high_risk_found)[:5])
            more = f" (+{len(high_risk_found) - 5} more)" if len(high_risk_found) > 5 else ""
            missing.append(f"High-risk ports exposed: {shown}{more}")
            risks.append("Exposed remote access and file-sharing services are frequently targeted by attackers.")

        # 3) Overall internet exposure
        if shodan_result.not_indexed:
            score += 1
            present.append("Not indexed in Shodan InternetDB (lower observed exposure)")
        else:
            port_count = len(shodan_result.ports or [])
            if port_count <= 5:
                score += 1
                present.append(f"Limited exposed services ({port_count} open port(s))")
            else:
                missing.append(f"Many exposed services ({port_count} open port(s))")
                risks.append("More exposed services increases the attack surface and the chance of misconfiguration.")

        desc = " ; ".join(missing[:2]) if missing else "Low internet exposure indicators"

        return ScoreDimension(
            name="Technical Hygiene",
            score=score,
            max_score=max_score,
            description=desc,
            present=present,
            missing=missing,
            risks=risks,
        )
    
    def _score_tls_certificate(self, ssl_result: Optional[SSLScanResult]) -> ScoreDimension:
        """Score TLS certificate from SSL results."""
        if not ssl_result:
            return ScoreDimension(
                name="TLS Certificate",
                score=1,
                analyzed=False,
                description="Not analyzed (TLS scan failed or timed out)"
            )

        max_score = 3
        score = 0
        present: List[str] = []
        missing: List[str] = []
        risks: List[str] = []

        if ssl_result.certificate_valid:
            score += 1
            present.append("Valid TLS certificate")
        else:
            missing.append("No valid TLS certificate (browser trust may fail)")
            risks.append("Invalid TLS can block users and enables interception warnings that reduce trust.")
            return ScoreDimension(
                name="TLS Certificate",
                score=0,
                max_score=max_score,
                description="No valid TLS certificate",
                present=present,
                missing=missing,
                risks=risks,
            )

        # Expiry hygiene
        if ssl_result.days_until_expiry is None:
            missing.append("Certificate expiry could not be determined")
        elif ssl_result.days_until_expiry >= 90:
            score += 1
            present.append(f"Certificate validity window is healthy ({ssl_result.days_until_expiry} days left)")
        else:
            missing.append(f"Certificate expires soon ({ssl_result.days_until_expiry} days left)")
            risks.append("Expiring certificates can cause outages and loss of trust if renewal fails.")

        # Protocol
        proto = (ssl_result.protocol_version or "").lower()
        if "tlsv1.3" in proto or "tlsv1.2" in proto:
            score += 1
            present.append(f"Modern TLS protocol in use ({ssl_result.protocol_version})")
        else:
            missing.append(f"Outdated TLS protocol detected ({ssl_result.protocol_version or 'unknown'})")
            risks.append("Older TLS versions can be incompatible and may expose weaker cryptography.")

        desc = "; ".join(missing[:2]) if missing else f"Strong TLS configuration ({ssl_result.protocol_version})"

        return ScoreDimension(
            name="TLS Certificate",
            score=score,
            max_score=max_score,
            description=desc,
            present=present,
            missing=missing,
            risks=risks,
        )
    
    def _score_http_headers(self, headers_result: Optional[HeadersScanResult]) -> ScoreDimension:
        """Score HTTP security headers."""
        if not headers_result:
            return ScoreDimension(
                name="HTTP Headers",
                score=1,
                analyzed=False,
                description="Not analyzed (headers scan failed or timed out)"
            )
        
        max_score = 6
        score = int(headers_result.headers_score)
        grade = headers_result.grade

        header_help = {
            "Strict-Transport-Security": "forces HTTPS and prevents downgrade attacks",
            "Content-Security-Policy": "reduces XSS/injection impact by restricting content sources",
            "X-Content-Type-Options": "prevents content-type sniffing",
            "X-Frame-Options": "reduces clickjacking risk",
            "Referrer-Policy": "limits referrer data leakage",
            "Permissions-Policy": "limits risky browser features",
        }
        header_risks = {
            "Strict-Transport-Security": "Without HSTS, visitors can be downgraded to insecure HTTP on hostile networks.",
            "Content-Security-Policy": "Without CSP, a single injected script can more easily steal sessions or redirect visitors.",
            "X-Content-Type-Options": "Without this header, browsers may interpret files as executable content in edge cases.",
            "X-Frame-Options": "Without this header, the site can be embedded and used in clickjacking scenarios.",
        }

        present = [f"{h} enabled" for h in sorted(headers_result.headers_present.keys())]
        missing = [
            f"{h} missing ({header_help.get(h, 'security hardening')})"
            for h in headers_result.headers_missing
        ]
        risks = [header_risks[h] for h in headers_result.headers_missing if h in header_risks]

        if headers_result.headers_missing:
            short_missing = ", ".join(headers_result.headers_missing[:3])
            if len(headers_result.headers_missing) > 3:
                short_missing += f" (+{len(headers_result.headers_missing) - 3} more)"
            desc = f"Grade {grade} — missing {len(headers_result.headers_missing)}/{max_score} headers ({short_missing})"
        else:
            desc = f"Grade {grade} — all {max_score}/{max_score} headers present"

        return ScoreDimension(
            name="HTTP Headers",
            score=score,
            max_score=max_score,
            description=desc,
            present=present,
            missing=missing,
            risks=risks,
        )
    
    def _score_cookie_compliance(self, cookie_result: Optional[CookieScanResult]) -> ScoreDimension:
        """Score cookie/GDPR compliance."""
        if not cookie_result:
            return ScoreDimension(
                name="Cookie Compliance",
                score=1,
                analyzed=False,
                description="Not analyzed (cookie scan failed or timed out)"
            )
        
        max_score = 4
        score = 0
        present: List[str] = []
        missing: List[str] = []
        risks: List[str] = []

        # Point 1/4: Consent banner / explicit consent flow
        if cookie_result.consent_banner_detected:
            provider = cookie_result.consent_provider or "consent provider detected"
            present.append(f"Consent banner detected ({provider})")
            score += 1
        else:
            missing.append("Consent banner not detected (consent flow unclear)")
            risks.append(
                "If tracking starts without a clear consent choice, this can create GDPR/ePrivacy exposure and reputational risk."
            )

        # Points 2-4/4: Tracking should not start before consent (3 slots)
        trackers = list(cookie_result.tracking_cookies or [])
        for i in range(3):
            if i < len(trackers):
                missing.append(f"Tracking cookie set before consent: {trackers[i]}")
                if not risks:
                    risks.append(
                        "Tracking before consent can lead to complaints, fines, and reduced visitor trust."
                    )
            else:
                present.append(f"No tracking cookie set before consent (check {i+1}/3)")
                score += 1

        score = max(0, min(max_score, score))
        extra = f" (+{len(trackers) - 3} more)" if len(trackers) > 3 else ""
        desc = f"{cookie_result.compliance_status}: {len(trackers)} tracking cookie(s) before consent{extra}"

        return ScoreDimension(
            name="Cookie Compliance",
            score=score,
            max_score=max_score,
            description=desc,
            present=present,
            missing=missing,
            risks=risks,
        )
    
    def _score_attack_surface(self, subdomain_result: Optional[SubdomainScanResult]) -> ScoreDimension:
        """Score attack surface from subdomain discovery."""
        if not subdomain_result:
            return ScoreDimension(
                name="Attack Surface",
                score=1,
                analyzed=False,
                description="Not analyzed (subdomain scan failed or timed out)"
            )
        
        max_score = 4
        risky_count = len(subdomain_result.risky_subdomains)
        score = max(0, max_score - min(max_score, risky_count))

        present: List[str] = []
        missing: List[str] = []
        risks: List[str] = []

        # Map the 4 points to the top 4 risky subdomain candidates.
        top = list(subdomain_result.risky_subdomains or [])[:4]
        for i in range(4):
            if i < len(top):
                item = top[i] or {}
                missing.append(
                    f"Risky subdomain exposed: {item.get('subdomain')} ({item.get('reason')})"
                )
                if not risks:
                    risks.append(
                        "Test/staging/admin subdomains are often less protected and can be used as an entry point."
                    )
            else:
                present.append(f"No additional risky subdomain found (check {i+1}/4)")

        desc = f"{risky_count} risky subdomain(s) (out of {subdomain_result.total_count} discovered)"

        return ScoreDimension(
            name="Attack Surface",
            score=score,
            max_score=max_score,
            description=desc,
            present=present,
            missing=missing,
            risks=risks,
        )
    
    def _score_tech_stack(self, techstack_result: Optional[TechStackScanResult]) -> ScoreDimension:
        """Score tech stack hygiene."""
        if not techstack_result:
            return ScoreDimension(
                name="Tech Stack",
                score=1,
                analyzed=False,
                description="Not analyzed (tech stack scan failed or timed out)"
            )
        
        max_score = 4
        score = 4
        present: List[str] = []
        missing: List[str] = []
        risks: List[str] = []

        # Points 1-3/4: Outdated components (3 slots)
        outdated = list(techstack_result.outdated_software or [])
        for i in range(3):
            if i < len(outdated):
                item = outdated[i] or {}
                sw = item.get("software", "Software")
                ver = item.get("version", "").strip()
                issue = item.get("issue", "outdated")
                missing.append(f"Outdated component: {sw}{(' ' + ver) if ver else ''} ({issue})")
            else:
                present.append(f"No additional outdated component detected (check {i+1}/3)")

        score -= min(3, len(outdated))
        if len(outdated) > 0:
            risks.append("Outdated components are a common source of known vulnerabilities and successful attacks.")

        # Point 4/4: Version leakage
        if techstack_result.version_leaks:
            score -= 1
            missing.append("Server/software versions are exposed via headers (makes targeting easier)")
            if len(risks) < 2:
                risks.append("Version leakage helps attackers focus on known exploits for specific software versions.")
        else:
            present.append("No obvious version leakage via headers")

        score = max(0, score)
        cms = f" (CMS: {techstack_result.cms_detected})" if techstack_result.cms_detected else ""
        desc = "; ".join(missing[:2]) + cms if missing else f"No major tech stack hygiene gaps detected{cms}"

        return ScoreDimension(
            name="Tech Stack",
            score=score,
            max_score=max_score,
            description=desc,
            present=present,
            missing=missing,
            risks=risks,
        )
    
    def _score_security_communication(self, website_result: Optional[WebsiteScanResult]) -> ScoreDimension:
        """Score security communication from website results."""
        if not website_result:
            return ScoreDimension(
                name="Security Communication",
                score=1,
                analyzed=False,
                description="Not analyzed (website scan failed or timed out)"
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
                score=1,
                analyzed=False,
                description="Not analyzed (website scan failed or timed out)"
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
                score=1,
                analyzed=False,
                description="Not analyzed (jobs scan failed or timed out)"
            )
        
        max_score = 2
        score = int(jobs_result.score or 0)

        present: List[str] = []
        missing: List[str] = []
        risks: List[str] = []

        # Point 1/2: Careers/jobs page discoverable
        if jobs_result.jobs_page_found:
            present.append("Careers/jobs page found")
        else:
            missing.append("No careers/jobs page found (hard to verify hiring signals)")
            risks.append("Without clear hiring visibility, it's harder to demonstrate security capacity and maturity.")

        # Point 2/2: Security roles visible
        if (jobs_result.security_jobs_found or 0) > 0:
            count = int(jobs_result.security_jobs_found or 0)
            present.append(f"Security hiring visible ({count} role{'s' if count != 1 else ''})")
        else:
            missing.append("No security roles visible on the careers pages checked")
            if not risks:
                risks.append("Limited visible security staffing can slow improvements and incident response readiness.")

        # Keep the existing 0/1/2 score semantics but ensure max_score and findings exist.
        score = max(0, min(max_score, score))

        if score == 0:
            desc = "No jobs page found"
        elif score == 1:
            desc = "Jobs page found, but no security roles visible"
        else:
            desc = "Security hiring visible on careers pages"
        
        return ScoreDimension(
            name="Security Hiring",
            score=score,
            max_score=max_score,
            description=desc,
            present=present,
            missing=missing,
            risks=risks,
        )
    
    def _score_security_leadership(self, governance_result: Optional[GovernanceScanResult]) -> ScoreDimension:
        """Score security leadership from governance scan."""
        if not governance_result:
            return ScoreDimension(
                name="Security Leadership",
                score=1,
                analyzed=False,
                description="Not analyzed (governance scan failed or timed out)"
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
                score=1,
                analyzed=False,
                description="Not analyzed (admin scan failed or timed out)"
            )
        
        max_score = 4
        total_found = len(admin_result.admin_pages_found) + len(admin_result.login_pages_found)
        exposed = int(admin_result.exposed_without_mfa or 0)

        score = max(0, max_score - min(max_score, exposed))
        present: List[str] = []
        missing: List[str] = []
        risks: List[str] = []

        if total_found == 0:
            present.append("No common admin/login endpoints responded")
        else:
            present.append(f"{total_found} admin/login endpoint(s) responded")

        if admin_result.sso_providers_detected:
            present.append("SSO/MFA indicators: " + ", ".join(admin_result.sso_providers_detected[:3]))

        if exposed > 0:
            missing.append(f"{exposed} endpoint(s) exposed without clear MFA/SSO protection")
            risks.append("Admin and login endpoints are high-value targets and are frequently abused for credential attacks.")
        else:
            present.append("No endpoints flagged as exposed without MFA")

        desc = "; ".join(missing[:2]) if missing else "No obvious exposed admin/login risk detected"

        return ScoreDimension(
            name="Admin Exposure",
            score=score,
            max_score=max_score,
            description=desc,
            present=present,
            missing=missing,
            risks=risks,
        )
    
    def _determine_tier(self, total_score: float, max_score: float) -> LeadTier:
        """Determine lead tier from score percentage (lower = more gaps)."""
        if max_score <= 0:
            return LeadTier.WARM

        pct = total_score / max_score
        if pct <= 0.45:
            return LeadTier.HOT
        elif pct <= 0.75:
            return LeadTier.WARM
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
        candidates: List[tuple[int, str]] = []

        for dim_name, dim in self._get_all_dimensions(lead):
            if not dim or not dim.analyzed:
                continue
            for msg in dim.missing:
                pr = 50
                if "Content-Security-Policy" in msg:
                    pr = 10
                elif "Strict-Transport-Security" in msg:
                    pr = 11
                elif "expires" in msg.lower():
                    pr = 12
                elif "DMARC" in msg:
                    pr = 13
                elif "High-risk ports" in msg:
                    pr = 14
                elif msg.lower().startswith("outdated software"):
                    pr = 20
                elif "Tracking cookies" in msg:
                    pr = 30
                candidates.append((pr, f"{dim_name}: {msg}"))

        candidates.sort(key=lambda x: x[0])
        return [m for _, m in candidates[:5]]
    
    def _generate_sales_angles(self, lead: LeadScore) -> List[str]:
        """Generate specific sales approach recommendations."""
        angles: List[str] = []

        suggestions = {
            "HTTP Headers": "Implement missing security headers using a standard hardening baseline and validate after deployment.",
            "TLS Certificate": "Automate certificate renewal and set up expiry monitoring alerts.",
            "Email Security": "Roll out SPF/DKIM/DMARC enforcement in stages (monitor â†’ quarantine â†’ reject).",
            "Cookie Compliance": "Block tracking until consent and document the consent mechanism for auditability.",
            "Attack Surface": "Restrict or remove risky subdomains; unused endpoints should be decommissioned.",
            "Technical Hygiene": "Reduce exposed services and prioritize patching of any known vulnerabilities.",
            "Tech Stack": "Patch/upgrade outdated components and reduce version leakage in headers.",
            "Admin Exposure": "Protect admin/login endpoints behind SSO/MFA and add rate limiting.",
        }

        for dim_name, dim in self._get_all_dimensions(lead):
            if not dim or not dim.analyzed or not dim.missing:
                continue
            present = dim.present[0] if dim.present else "Some controls present"
            missing = dim.missing[0]
            risk = dim.risks[0] if dim.risks else "This increases security and compliance risk."
            next_step = suggestions.get(dim_name, "Address the missing controls and re-validate the posture.")
            angles.append(
                f"{dim_name}: Present: {present}. Missing: {missing}. Risk: {risk} Next step: {next_step}"
            )
            if len(angles) >= 3:
                break

        if not angles:
            angles.append(
                "No high-signal gaps detected in this scan; propose a short assessment to confirm the current posture and improvements."
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
        analyzed_dims = sum(1 for _, dim in all_dims if dim and dim.analyzed)

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
            f"over {total_dims} dimensies (waarvan {analyzed_dims} geanalyseerd), wat wijst op "
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
