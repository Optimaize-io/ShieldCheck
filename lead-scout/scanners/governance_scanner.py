"""
Governance Scanner - Leadership & Annual Report Analysis
Scans company websites for:
1. Security leadership visibility (CISO, Security Officer, etc.)
2. Annual reports with cyber risk mentions
"""

import requests
import logging
import re
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from bs4 import BeautifulSoup
from io import BytesIO
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

# Try to import pdfplumber, but make it optional
try:
    import pdfplumber
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False
    logger.warning("pdfplumber not installed - PDF analysis disabled")


@dataclass
class GovernanceScanResult:
    """Results from governance scanning."""
    domain: str
    
    # Leadership detection
    leadership_page_found: bool = False
    leadership_page_url: Optional[str] = None
    security_leaders_found: List[str] = field(default_factory=list)
    security_titles_found: List[str] = field(default_factory=list)
    has_visible_ciso: bool = False
    
    # Annual report analysis
    annual_report_found: bool = False
    annual_report_url: Optional[str] = None
    annual_report_year: Optional[str] = None
    cyber_mentions_in_report: int = 0
    risk_keywords_found: List[str] = field(default_factory=list)
    
    # Pages checked
    pages_checked: List[str] = field(default_factory=list)
    
    # Scoring
    leadership_score: int = 0  # 0-2
    report_score: int = 0  # 0-2
    total_score: int = 0  # Combined
    findings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "leadership_page_found": self.leadership_page_found,
            "leadership_page_url": self.leadership_page_url,
            "security_leaders_found": self.security_leaders_found,
            "security_titles_found": self.security_titles_found,
            "has_visible_ciso": self.has_visible_ciso,
            "annual_report_found": self.annual_report_found,
            "annual_report_url": self.annual_report_url,
            "annual_report_year": self.annual_report_year,
            "cyber_mentions_in_report": self.cyber_mentions_in_report,
            "risk_keywords_found": self.risk_keywords_found,
            "pages_checked": self.pages_checked,
            "leadership_score": self.leadership_score,
            "report_score": self.report_score,
            "total_score": self.total_score,
            "findings": self.findings,
            "error": self.error
        }


class GovernanceScanner:
    """
    Scans company websites for security governance indicators:
    1. Visible security leadership (CISO, Security Officer, DPO)
    2. Annual reports mentioning cyber risks
    """
    
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    # Pages to check for leadership/team info
    LEADERSHIP_PATHS = [
        "/team",
        "/ons-team",
        "/over-ons",
        "/about",
        "/about-us",
        "/management",
        "/directie",
        "/bestuur",
        "/leadership",
        "/leiderschap",
        "/organisatie",
        "/wie-zijn-wij",
        "/about/team",
        "/about/leadership",
        "/over-ons/team",
        "/corporate/management",
        "/nl/over-ons",
        "/en/about",
    ]
    
    # Security leadership titles to look for
    SECURITY_TITLES = [
        # C-level and strategic
        ("ciso", "CISO"),
        ("chief information security officer", "Chief Information Security Officer"),
        ("chief security officer", "Chief Security Officer"),
        ("cso", "CSO"),
        
        # Security management
        ("security officer", "Security Officer"),
        ("information security officer", "Information Security Officer"),
        ("information security manager", "Information Security Manager"),
        ("security manager", "Security Manager"),
        ("head of security", "Head of Security"),
        ("director of security", "Director of Security"),
        ("security director", "Security Director"),
        
        # Privacy/DPO
        ("privacy officer", "Privacy Officer"),
        ("data protection officer", "Data Protection Officer"),
        ("dpo", "DPO"),
        ("functionaris gegevensbescherming", "Functionaris Gegevensbescherming"),
        
        # Risk/Compliance
        ("chief risk officer", "Chief Risk Officer"),
        ("risk manager", "Risk Manager"),
        ("compliance officer", "Compliance Officer"),
        
        # Dutch variants
        ("beveiligingsmanager", "Beveiligingsmanager"),
        ("hoofd informatiebeveiliging", "Hoofd Informatiebeveiliging"),
    ]
    
    # Paths/patterns for annual reports
    REPORT_PATHS = [
        "/jaarverslag",
        "/annual-report",
        "/investors",
        "/investeerders",
        "/publicaties",
        "/publications",
        "/downloads",
        "/documents",
        "/documenten",
        "/investor-relations",
        "/ir",
    ]
    
    # Keywords indicating cyber/security in reports
    CYBER_KEYWORDS = [
        "cyber", "cybersecurity", "cyberbeveiliging",
        "informatiebeveiliging", "information security",
        "nis2", "cyberbeveiligingswet",
        "ransomware", "phishing",
        "data breach", "datalek",
        "security incident", "beveiligingsincident",
        "iso 27001", "iso27001",
        "soc 2", "soc2",
        "gdpr", "avg",
        "hacking", "hackers",
    ]
    
    def __init__(self, timeout: float = 10.0):
        """Initialize governance scanner."""
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/pdf",
            "Accept-Language": "nl,en;q=0.9",
        })
    
    def scan(self, domain: str) -> GovernanceScanResult:
        """
        Scan a domain for governance indicators.
        
        Args:
            domain: Domain to scan (e.g., "cosun.nl")
            
        Returns:
            GovernanceScanResult with findings
        """
        result = GovernanceScanResult(domain=domain)
        
        try:
            # 1. Scan for security leadership
            self._scan_leadership(domain, result)
            
            # 2. Scan for annual reports
            self._scan_annual_reports(domain, result)
            
            # Calculate scores
            result.leadership_score = self._calculate_leadership_score(result)
            result.report_score = self._calculate_report_score(result)
            result.total_score = (result.leadership_score + result.report_score) // 2
            
            # Generate findings summary
            self._generate_findings(result)
            
        except Exception as e:
            logger.error(f"Governance scan failed for {domain}: {e}")
            result.error = str(e)
            result.findings.append(f"⚠️ Governance scan error: {str(e)[:50]}")
        
        return result
    
    def _scan_leadership(self, domain: str, result: GovernanceScanResult) -> None:
        """Scan for security leadership on team/about pages."""
        for path in self.LEADERSHIP_PATHS:
            url = f"https://{domain}{path}"
            result.pages_checked.append(url)
            
            try:
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                
                if response.status_code == 200:
                    content_lower = response.text.lower()
                    
                    # Check if this looks like a team/about page
                    if any(kw in content_lower for kw in ["team", "management", "directie", "over ons", "about"]):
                        result.leadership_page_found = True
                        result.leadership_page_url = url
                        
                        # Search for security titles
                        for search_term, display_name in self.SECURITY_TITLES:
                            if search_term in content_lower:
                                if display_name not in result.security_titles_found:
                                    result.security_titles_found.append(display_name)
                                
                                # Check for CISO specifically
                                if "ciso" in search_term or "chief information security" in search_term:
                                    result.has_visible_ciso = True
                                
                                # Try to extract name context
                                self._extract_leader_names(response.text, search_term, result)
                        
                        # If we found security titles, we can stop
                        if result.security_titles_found:
                            break
                            
            except requests.exceptions.RequestException:
                continue
    
    def _extract_leader_names(self, html: str, title: str, result: GovernanceScanResult) -> None:
        """Try to extract names associated with security titles."""
        soup = BeautifulSoup(html, 'html.parser')
        text = soup.get_text()
        
        # Look for patterns like "Name - Title" or "Title: Name"
        patterns = [
            rf'([A-Z][a-z]+ [A-Z][a-z]+)\s*[-–]\s*{re.escape(title)}',
            rf'{re.escape(title)}\s*[-–:]\s*([A-Z][a-z]+ [A-Z][a-z]+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches[:1]:  # Just first match
                if match and len(match) > 3:
                    leader_entry = f"{match} ({title})"
                    if leader_entry not in result.security_leaders_found:
                        result.security_leaders_found.append(leader_entry)
    
    def _scan_annual_reports(self, domain: str, result: GovernanceScanResult) -> None:
        """Scan for annual reports and analyze them for cyber mentions."""
        pdf_links = []
        
        # First, find pages that might have annual report links
        for path in self.REPORT_PATHS:
            url = f"https://{domain}{path}"
            
            try:
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find PDF links
                    for link in soup.find_all('a', href=True):
                        href = link.get('href', '')
                        link_text = link.get_text().lower()
                        
                        # Look for annual report PDFs
                        if '.pdf' in href.lower():
                            if any(kw in href.lower() or kw in link_text for kw in 
                                   ['jaarverslag', 'annual', 'report', 'jaarbericht']):
                                full_url = urljoin(url, href)
                                if full_url not in pdf_links:
                                    pdf_links.append(full_url)
                                    
                                    # Try to extract year
                                    year_match = re.search(r'20[12][0-9]', href + link_text)
                                    if year_match:
                                        result.annual_report_year = year_match.group()
                                        
            except requests.exceptions.RequestException:
                continue
        
        # Try to download and analyze the most recent report
        if pdf_links and PDF_SUPPORT:
            for pdf_url in pdf_links[:2]:  # Try first 2 PDFs
                if self._analyze_pdf(pdf_url, result):
                    break
        elif pdf_links:
            # PDF found but can't analyze
            result.annual_report_found = True
            result.annual_report_url = pdf_links[0]
            result.findings.append("ℹ️ Annual report PDF found but pdfplumber not installed")
    
    def _analyze_pdf(self, pdf_url: str, result: GovernanceScanResult) -> bool:
        """Download and analyze a PDF for cyber mentions."""
        try:
            response = self.session.get(pdf_url, timeout=30, stream=True)
            if response.status_code != 200:
                return False
            
            # Limit download size (10MB max)
            content_length = int(response.headers.get('content-length', 0))
            if content_length > 10 * 1024 * 1024:
                logger.warning(f"PDF too large: {content_length} bytes")
                return False
            
            result.annual_report_found = True
            result.annual_report_url = pdf_url
            
            # Analyze with pdfplumber
            pdf_bytes = BytesIO(response.content)
            
            with pdfplumber.open(pdf_bytes) as pdf:
                # Sample pages (first 20 + last 20 for risk section)
                pages_to_check = list(range(min(20, len(pdf.pages))))
                if len(pdf.pages) > 40:
                    pages_to_check.extend(range(len(pdf.pages) - 20, len(pdf.pages)))
                
                all_text = ""
                for page_num in pages_to_check:
                    if page_num < len(pdf.pages):
                        page = pdf.pages[page_num]
                        text = page.extract_text() or ""
                        all_text += text.lower() + " "
                
                # Search for cyber keywords
                for keyword in self.CYBER_KEYWORDS:
                    count = all_text.count(keyword.lower())
                    if count > 0:
                        result.cyber_mentions_in_report += count
                        if keyword not in result.risk_keywords_found:
                            result.risk_keywords_found.append(keyword)
            
            return True
            
        except Exception as e:
            logger.warning(f"PDF analysis failed for {pdf_url}: {e}")
            return False
    
    def _calculate_leadership_score(self, result: GovernanceScanResult) -> int:
        """Calculate score for security leadership visibility."""
        if result.has_visible_ciso:
            return 2  # Excellent - has CISO
        elif result.security_titles_found:
            return 1  # Some security leadership visible
        else:
            return 0  # No security leadership found
    
    def _calculate_report_score(self, result: GovernanceScanResult) -> int:
        """Calculate score for annual report cyber mentions."""
        if result.cyber_mentions_in_report >= 10:
            return 2  # Significant cyber awareness
        elif result.cyber_mentions_in_report > 0 or result.annual_report_found:
            return 1  # Some awareness or report found
        else:
            return 0  # No report or cyber mentions
    
    def _generate_findings(self, result: GovernanceScanResult) -> None:
        """Generate human-readable findings."""
        findings = []
        
        # Leadership findings
        if result.has_visible_ciso:
            findings.append("✅ CISO or equivalent role publicly visible")
        elif result.security_titles_found:
            findings.append(f"🟡 Security-related roles found: {', '.join(result.security_titles_found[:3])}")
        else:
            findings.append("❌ No security leadership roles found on website")
            findings.append("   → NIS2 requires board-level security accountability")
        
        if result.security_leaders_found:
            for leader in result.security_leaders_found[:2]:
                findings.append(f"   • {leader}")
        
        # Annual report findings
        if result.annual_report_found:
            findings.append(f"✅ Annual report found: {result.annual_report_year or 'year unknown'}")
            
            if result.cyber_mentions_in_report > 0:
                findings.append(f"✅ {result.cyber_mentions_in_report} cyber/security mentions in report")
                if result.risk_keywords_found:
                    findings.append(f"   Keywords: {', '.join(result.risk_keywords_found[:5])}")
            else:
                findings.append("⚠️ No cyber/security mentions found in annual report")
        else:
            findings.append("⚠️ No annual report found on website")
        
        result.findings = findings
