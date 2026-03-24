"""
Jobs Scanner - Security Vacancy Detection
Scans career/jobs pages for security-related positions.
No security hiring = potential governance gap.
"""

import requests
import logging
import re
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class JobsScanResult:
    """Results from jobs/vacancy scanning."""
    domain: str
    jobs_page_found: bool = False
    jobs_page_url: Optional[str] = None
    total_jobs_found: int = 0
    security_jobs_found: int = 0
    security_job_titles: List[str] = field(default_factory=list)
    security_keywords_found: List[str] = field(default_factory=list)
    pages_checked: List[str] = field(default_factory=list)
    score: int = 2  # Default good score (has security hiring)
    findings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "jobs_page_found": self.jobs_page_found,
            "jobs_page_url": self.jobs_page_url,
            "total_jobs_found": self.total_jobs_found,
            "security_jobs_found": self.security_jobs_found,
            "security_job_titles": self.security_job_titles,
            "security_keywords_found": self.security_keywords_found,
            "pages_checked": self.pages_checked,
            "score": self.score,
            "findings": self.findings,
            "error": self.error
        }


class JobsScanner:
    """
    Scans company career pages for security-related job postings.
    Lack of security hiring in a large company = governance gap.
    """
    
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    # Common jobs/careers page paths
    JOBS_PATHS = [
        "/vacatures",
        "/jobs",
        "/careers",
        "/werkenbij",
        "/werken-bij",
        "/werken-bij-ons",
        "/career",
        "/vacature",
        "/join",
        "/join-us",
        "/over-ons/vacatures",
        "/about/careers",
        "/nl/vacatures",
        "/en/careers",
    ]
    
    # Security-related keywords to search for in job listings
    SECURITY_KEYWORDS = [
        # Titles
        "ciso", "chief information security", "security officer",
        "information security", "cyber security", "cybersecurity",
        "security manager", "security analyst", "security engineer",
        "security architect", "security consultant", "soc analyst",
        "penetration tester", "pentest", "ethical hacker",
        "security operations", "security specialist",
        "privacy officer", "data protection", "dpo",
        "risk manager", "compliance officer", "grc",
        
        # Certifications/frameworks often in job descriptions
        "cissp", "cism", "cisa", "oscp", "ceh",
        "iso 27001", "iso27001", "nis2", "soc 2", "soc2",
        
        # Dutch terms
        "beveiligingsmanager", "informatiebeveiliging",
        "functionaris gegevensbescherming", "fg",
    ]
    
    def __init__(self, timeout: float = 10.0):
        """Initialize jobs scanner."""
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "nl,en;q=0.9",
        })
    
    def scan(self, domain: str) -> JobsScanResult:
        """
        Scan a domain for security job postings.
        
        Args:
            domain: Domain to scan (e.g., "cosun.nl")
            
        Returns:
            JobsScanResult with findings
        """
        result = JobsScanResult(domain=domain)
        
        try:
            # Try to find a jobs/careers page
            jobs_page_content = None
            
            for path in self.JOBS_PATHS:
                url = f"https://{domain}{path}"
                result.pages_checked.append(url)
                
                try:
                    response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                    
                    if response.status_code == 200:
                        # Check if it looks like a jobs page
                        content_lower = response.text.lower()
                        if any(kw in content_lower for kw in ["vacature", "job", "career", "werken", "sollicit"]):
                            result.jobs_page_found = True
                            result.jobs_page_url = url
                            jobs_page_content = response.text
                            logger.info(f"Found jobs page at {url}")
                            break
                            
                except requests.exceptions.RequestException:
                    continue
            
            if jobs_page_content:
                # Parse the jobs page for security positions
                self._analyze_jobs_page(jobs_page_content, result)
            else:
                result.findings.append("⚠️ No careers/jobs page found")
            
            # Calculate score
            result.score = self._calculate_score(result)
            
            # Generate findings summary
            self._generate_findings(result)
            
        except Exception as e:
            logger.error(f"Jobs scan failed for {domain}: {e}")
            result.error = str(e)
            result.score = 1  # Unknown state
            result.findings.append(f"⚠️ Jobs scan error: {str(e)[:50]}")
        
        return result
    
    def _analyze_jobs_page(self, html_content: str, result: JobsScanResult) -> None:
        """Analyze jobs page content for security positions."""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Get all text content
        text_content = soup.get_text().lower()
        
        # Try to count total jobs (look for common patterns)
        # This is approximate - different sites structure differently
        job_elements = soup.find_all(['article', 'div', 'li'], 
                                      class_=re.compile(r'job|vacature|position|opening', re.I))
        if job_elements:
            result.total_jobs_found = len(job_elements)
        
        # Search for security keywords
        found_keywords = set()
        security_titles = []
        
        for keyword in self.SECURITY_KEYWORDS:
            if keyword in text_content:
                found_keywords.add(keyword)
                
                # Try to extract the job title context
                pattern = rf'.{{0,50}}{re.escape(keyword)}.{{0,50}}'
                matches = re.findall(pattern, text_content, re.IGNORECASE)
                for match in matches[:2]:  # Limit to avoid spam
                    clean_match = ' '.join(match.split())
                    if clean_match not in security_titles:
                        security_titles.append(clean_match)
        
        result.security_keywords_found = list(found_keywords)
        result.security_job_titles = security_titles[:5]  # Limit output
        result.security_jobs_found = len(found_keywords)
    
    def _calculate_score(self, result: JobsScanResult) -> int:
        """
        Calculate security hiring score.
        
        Score logic:
        - 2: Security jobs/keywords found = active hiring
        - 1: Jobs page exists but no security roles
        - 0: No jobs page or evidence of security hiring
        """
        if result.security_jobs_found > 0:
            return 2
        elif result.jobs_page_found:
            return 1
        else:
            return 0
    
    def _generate_findings(self, result: JobsScanResult) -> None:
        """Generate human-readable findings."""
        findings = result.findings.copy()
        
        if result.jobs_page_found:
            findings.append(f"ℹ️ Jobs page found: {result.jobs_page_url}")
            
            if result.total_jobs_found > 0:
                findings.append(f"ℹ️ ~{result.total_jobs_found} job listings detected")
            
            if result.security_jobs_found > 0:
                findings.append(f"✅ {result.security_jobs_found} security-related keyword(s) found")
                for kw in result.security_keywords_found[:5]:
                    findings.append(f"   • {kw}")
            else:
                findings.append("❌ No security job postings found")
                findings.append("   → Potential governance gap: no visible security hiring")
        else:
            findings.append("⚠️ Could not find careers/jobs page")
        
        result.findings = findings
