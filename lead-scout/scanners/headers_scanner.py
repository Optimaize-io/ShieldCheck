"""
HTTP Security Headers Scanner
Checks for presence of important security headers and information leakage.
"""

import requests
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class HeadersScanResult:
    """Results from HTTP security headers scanning."""
    domain: str
    headers_present: Dict[str, str] = field(default_factory=dict)
    headers_missing: List[str] = field(default_factory=list)
    info_leakage: Dict[str, str] = field(default_factory=dict)
    grade: str = "F"
    headers_score: int = 0  # Out of 6
    score: int = 0  # 0-2 for scoring system
    findings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "headers_present": self.headers_present,
            "headers_missing": self.headers_missing,
            "info_leakage": self.info_leakage,
            "grade": self.grade,
            "headers_score": self.headers_score,
            "score": self.score,
            "findings": self.findings,
            "error": self.error
        }


class HeadersScanner:
    """
    Scans HTTP response headers for security best practices.
    """
    
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    # Security headers to check (6 total)
    SECURITY_HEADERS = {
        "Strict-Transport-Security": "HSTS - Forces HTTPS connections",
        "Content-Security-Policy": "CSP - Prevents XSS and injection attacks",
        "X-Content-Type-Options": "Prevents MIME-type sniffing",
        "X-Frame-Options": "Prevents clickjacking attacks",
        "Referrer-Policy": "Controls referrer information sharing",
        "Permissions-Policy": "Controls browser feature permissions",
    }
    
    # Headers that may leak sensitive info
    INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
    
    def __init__(self, timeout: float = 10.0):
        """Initialize headers scanner."""
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
        })
    
    def scan(self, domain: str, response: Optional[requests.Response] = None) -> HeadersScanResult:
        """
        Scan HTTP response headers for security issues.
        
        Args:
            domain: Domain to scan
            response: Optional existing response to analyze (to avoid extra request)
            
        Returns:
            HeadersScanResult with findings
        """
        result = HeadersScanResult(domain=domain)
        
        try:
            # Get response if not provided
            if response is None:
                url = f"https://{domain}"
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            headers = response.headers
            
            # Check security headers
            for header, description in self.SECURITY_HEADERS.items():
                if header in headers:
                    result.headers_present[header] = headers[header]
                else:
                    result.headers_missing.append(header)
            
            result.headers_score = len(result.headers_present)
            
            # Check for information leakage
            for header in self.INFO_LEAK_HEADERS:
                if header in headers:
                    result.info_leakage[header] = headers[header]
            
            # Calculate grade (A-F based on headers present)
            result.grade = self._calculate_grade(result.headers_score)
            
            # Calculate score (0-2)
            result.score = self._calculate_score(result)
            
            # Generate findings
            self._generate_findings(result)
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Headers scan failed for {domain}: {e}")
            result.error = str(e)
            result.score = 1  # Neutral on error
            result.findings.append(f"⚠️ Could not fetch headers: {str(e)[:50]}")
        
        return result
    
    def _calculate_grade(self, headers_count: int) -> str:
        """Calculate letter grade based on headers present (out of 6)."""
        if headers_count == 6:
            return "A"
        elif headers_count == 5:
            return "B"
        elif headers_count == 4:
            return "C"
        elif headers_count == 3:
            return "D"
        elif headers_count >= 1:
            return "E"
        else:
            return "F"
    
    def _calculate_score(self, result: HeadersScanResult) -> int:
        """
        Calculate security score.
        
        Score logic:
        - 2: Grade A or B (5-6 headers)
        - 1: Grade C or D (3-4 headers)
        - 0: Grade E or F (0-2 headers)
        """
        if result.grade in ["A", "B"]:
            return 2
        elif result.grade in ["C", "D"]:
            return 1
        else:
            return 0
    
    def _generate_findings(self, result: HeadersScanResult) -> None:
        """Generate human-readable findings."""
        findings = []
        
        # Grade summary
        findings.append(f"📊 Security Headers Grade: {result.grade} ({result.headers_score}/6 headers)")
        
        # Present headers
        if result.headers_present:
            for header in result.headers_present:
                findings.append(f"   ✅ {header}")
        
        # Missing headers
        if result.headers_missing:
            for header in result.headers_missing:
                findings.append(f"   ⚠️ Missing: {header}")
        
        # Information leakage
        if result.info_leakage:
            findings.append("🔍 Information Leakage Detected:")
            for header, value in result.info_leakage.items():
                findings.append(f"   ⚠️ {header}: {value}")
        
        result.findings = findings
