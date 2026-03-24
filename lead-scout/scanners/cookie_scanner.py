"""
Cookie Compliance Scanner
Checks for tracking cookies set before consent and cookie banner presence.
"""

import requests
import logging
import re
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass, field
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class CookieScanResult:
    """Results from cookie compliance scanning."""
    domain: str
    cookies_before_consent: List[Dict[str, str]] = field(default_factory=list)
    tracking_cookies: List[str] = field(default_factory=list)
    functional_cookies: List[str] = field(default_factory=list)
    unknown_cookies: List[str] = field(default_factory=list)
    consent_banner_detected: bool = False
    consent_provider: Optional[str] = None
    compliance_status: str = "UNKNOWN"
    score: int = 2  # Default good score
    findings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "cookies_before_consent": self.cookies_before_consent,
            "tracking_cookies": self.tracking_cookies,
            "functional_cookies": self.functional_cookies,
            "unknown_cookies": self.unknown_cookies,
            "consent_banner_detected": self.consent_banner_detected,
            "consent_provider": self.consent_provider,
            "compliance_status": self.compliance_status,
            "score": self.score,
            "findings": self.findings,
            "error": self.error
        }


class CookieScanner:
    """
    Scans for cookie compliance (GDPR/ePrivacy).
    Checks cookies set before consent and consent banner presence.
    """
    
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    # Tracking cookie patterns (name patterns)
    TRACKING_PATTERNS = [
        # Google Analytics
        r'^_ga$', r'^_gid$', r'^_gat', r'^__utm',
        # Facebook
        r'^_fbp$', r'^_fbc$', r'^fr$',
        # HubSpot
        r'^hubspot', r'^__hs', r'^__hstc', r'^__hssc', r'^__hssrc',
        # Hotjar
        r'^_hj', r'^hotjar',
        # LinkedIn
        r'^li_', r'^bcookie', r'^lidc',
        # Microsoft/Bing
        r'^_uet', r'^MUID',
        # Other common trackers
        r'^_clck', r'^_clsk',  # Clarity
        r'^_pk_', r'^_paq',  # Matomo/Piwik
        r'^IDE$', r'^DSID$',  # DoubleClick
        r'^NID$', r'^APISID$', r'^SSID$', r'^SID$',  # Google general
    ]
    
    # Functional cookie patterns
    FUNCTIONAL_PATTERNS = [
        r'^PHPSESSID$', r'^JSESSIONID$', r'^ASP\.NET',
        r'^csrf', r'^_csrf', r'^XSRF',
        r'^lang$', r'^locale$', r'^language$',
        r'^cookie_?consent', r'^cookieconsent',
        r'^session', r'^sess_',
        r'^__stripe',  # Payment (needed for functionality)
    ]
    
    # Cookie consent banner providers
    CONSENT_BANNERS = {
        "cookiebot": "Cookiebot",
        "onetrust": "OneTrust",
        "cookieconsent": "Cookie Consent",
        "tarteaucitron": "Tarteaucitron",
        "didomi": "Didomi",
        "quantcast": "Quantcast Choice",
        "trustarc": "TrustArc",
        "cookiepro": "CookiePro",
        "klaro": "Klaro",
        "cookiescript": "CookieScript",
        "iubenda": "Iubenda",
        "cookie-law": "Cookie Law Info",
        "gdpr-cookie": "GDPR Cookie Consent",
        "complianz": "Complianz",
    }
    
    def __init__(self, timeout: float = 10.0):
        """Initialize cookie scanner."""
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
        })
        # Compile regex patterns
        self.tracking_re = [re.compile(p, re.IGNORECASE) for p in self.TRACKING_PATTERNS]
        self.functional_re = [re.compile(p, re.IGNORECASE) for p in self.FUNCTIONAL_PATTERNS]
    
    def scan(self, domain: str, response: Optional[requests.Response] = None, 
             html_content: Optional[str] = None) -> CookieScanResult:
        """
        Scan for cookie compliance issues.
        
        Args:
            domain: Domain to scan
            response: Optional existing response (to avoid extra request)
            html_content: Optional HTML content for banner detection
            
        Returns:
            CookieScanResult with findings
        """
        result = CookieScanResult(domain=domain)
        
        try:
            # Get response if not provided
            if response is None:
                url = f"https://{domain}"
                # Use fresh session to simulate first visit
                fresh_session = requests.Session()
                fresh_session.headers.update({
                    "User-Agent": self.USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml",
                })
                response = fresh_session.get(url, timeout=self.timeout, allow_redirects=True)
                html_content = response.text
            
            # Analyze cookies from response
            self._analyze_cookies(response, result)
            
            # Check for consent banner in HTML
            if html_content:
                self._check_consent_banner(html_content, result)
            
            # Calculate compliance status and score
            result.score = self._calculate_score(result)
            result.compliance_status = self._determine_compliance_status(result)
            
            # Generate findings
            self._generate_findings(result)
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Cookie scan failed for {domain}: {e}")
            result.error = str(e)
            result.score = 1  # Neutral on error
            result.findings.append(f"⚠️ Could not analyze cookies: {str(e)[:50]}")
        
        return result
    
    def _analyze_cookies(self, response: requests.Response, result: CookieScanResult) -> None:
        """Analyze cookies from response."""
        for cookie in response.cookies:
            cookie_info = {
                "name": cookie.name,
                "domain": cookie.domain,
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                "samesite": cookie.get_nonstandard_attr("SameSite", "None"),
            }
            result.cookies_before_consent.append(cookie_info)
            
            # Classify cookie
            cookie_name = cookie.name
            
            if self._matches_patterns(cookie_name, self.tracking_re):
                result.tracking_cookies.append(cookie_name)
            elif self._matches_patterns(cookie_name, self.functional_re):
                result.functional_cookies.append(cookie_name)
            else:
                result.unknown_cookies.append(cookie_name)
    
    def _matches_patterns(self, name: str, patterns: List[re.Pattern]) -> bool:
        """Check if cookie name matches any pattern."""
        for pattern in patterns:
            if pattern.search(name):
                return True
        return False
    
    def _check_consent_banner(self, html: str, result: CookieScanResult) -> None:
        """Check for cookie consent banner in HTML."""
        html_lower = html.lower()
        
        for keyword, provider in self.CONSENT_BANNERS.items():
            if keyword in html_lower:
                result.consent_banner_detected = True
                result.consent_provider = provider
                return
        
        # Also check for generic patterns
        generic_patterns = [
            "cookie-notice", "cookie-banner", "cookie-popup",
            "gdpr-notice", "privacy-banner", "consent-manager",
        ]
        for pattern in generic_patterns:
            if pattern in html_lower:
                result.consent_banner_detected = True
                result.consent_provider = "Generic/Unknown"
                return
    
    def _calculate_score(self, result: CookieScanResult) -> int:
        """
        Calculate cookie compliance score.
        
        Score logic:
        - 2: Clean (no tracking cookies before consent) OR (banner + only functional)
        - 1: Banner present but tracking cookies leak
        - 0: Tracking cookies without consent banner
        """
        has_tracking = len(result.tracking_cookies) > 0
        has_banner = result.consent_banner_detected
        
        if not has_tracking:
            return 2  # Clean - no tracking cookies
        elif has_banner and has_tracking:
            return 1  # Banner but cookies leak
        else:
            return 0  # Tracking without consent
    
    def _determine_compliance_status(self, result: CookieScanResult) -> str:
        """Determine GDPR/ePrivacy compliance status."""
        has_tracking = len(result.tracking_cookies) > 0
        has_banner = result.consent_banner_detected
        
        if not has_tracking:
            return "COMPLIANT"
        elif has_banner and not has_tracking:
            return "COMPLIANT"
        elif has_banner and has_tracking:
            return "PARTIAL"
        else:
            return "NON_COMPLIANT"
    
    def _generate_findings(self, result: CookieScanResult) -> None:
        """Generate human-readable findings."""
        findings = []
        
        total_cookies = len(result.cookies_before_consent)
        findings.append(f"🍪 {total_cookies} cookie(s) set before any consent")
        
        # Tracking cookies
        if result.tracking_cookies:
            trackers = ", ".join(result.tracking_cookies[:5])
            if len(result.tracking_cookies) > 5:
                trackers += f" (+{len(result.tracking_cookies) - 5} more)"
            findings.append(f"❌ Tracking cookies: {trackers}")
            
            # Identify tracker sources
            tracker_sources = set()
            for cookie in result.tracking_cookies:
                if cookie.startswith('_ga') or cookie.startswith('_gid'):
                    tracker_sources.add("Google Analytics")
                elif cookie.startswith('_fb') or cookie == 'fr':
                    tracker_sources.add("Facebook")
                elif 'hubspot' in cookie.lower() or cookie.startswith('__hs'):
                    tracker_sources.add("HubSpot")
                elif cookie.startswith('_hj') or 'hotjar' in cookie.lower():
                    tracker_sources.add("Hotjar")
                elif cookie.startswith('li_'):
                    tracker_sources.add("LinkedIn")
            
            if tracker_sources:
                findings.append(f"   Sources: {', '.join(tracker_sources)}")
        else:
            findings.append("✅ No tracking cookies before consent")
        
        # Consent banner
        if result.consent_banner_detected:
            findings.append(f"✅ Cookie consent banner detected ({result.consent_provider})")
        else:
            findings.append("⚠️ No cookie consent banner detected")
        
        # Compliance status
        if result.compliance_status == "COMPLIANT":
            findings.append("✅ Cookie compliance: OK")
        elif result.compliance_status == "PARTIAL":
            findings.append("⚠️ Cookie compliance: PARTIAL - tracking despite banner")
        else:
            findings.append("❌ Cookie compliance: VIOLATION - tracking without consent")
        
        result.findings = findings
