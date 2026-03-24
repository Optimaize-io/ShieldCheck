"""
Admin Panel Scanner - Exposed Admin Page Detection
Checks for publicly accessible admin/login pages and MFA indicators.
IMPORTANT: Uses HEAD requests only to be non-intrusive.
"""

import requests
import logging
import re
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class AdminScanResult:
    """Results from admin panel scanning."""
    domain: str
    admin_pages_found: List[Dict[str, Any]] = field(default_factory=list)
    login_pages_found: List[Dict[str, Any]] = field(default_factory=list)
    mfa_indicators: List[str] = field(default_factory=list)
    sso_providers_detected: List[str] = field(default_factory=list)
    exposed_without_mfa: int = 0
    pages_checked: List[str] = field(default_factory=list)
    score: int = 2  # Default good score
    findings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "admin_pages_found": self.admin_pages_found,
            "login_pages_found": self.login_pages_found,
            "mfa_indicators": self.mfa_indicators,
            "sso_providers_detected": self.sso_providers_detected,
            "exposed_without_mfa": self.exposed_without_mfa,
            "pages_checked": self.pages_checked,
            "score": self.score,
            "findings": self.findings,
            "error": self.error
        }


class AdminScanner:
    """
    Scans for exposed admin/login pages and checks for MFA indicators.
    Uses HEAD requests where possible to minimize footprint.
    """
    
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    # Common admin/login paths to check
    ADMIN_PATHS = [
        # Generic admin
        "/admin",
        "/administrator",
        "/beheer",
        "/backend",
        "/manage",
        "/management",
        
        # WordPress
        "/wp-admin",
        "/wp-login.php",
        
        # Common CMS
        "/cms",
        "/cms/admin",
        "/sitecore",
        "/umbraco",
        "/sitefinity",
        
        # Portals
        "/portal",
        "/portaal",
        "/my",
        "/myaccount",
        "/mijn",
        
        # Login pages
        "/login",
        "/signin",
        "/sign-in",
        "/inloggen",
        "/auth",
        "/authenticate",
        "/sso",
        
        # API/Dev
        "/api",
        "/swagger",
        "/graphql",
        "/graphiql",
        
        # Common applications
        "/owa",  # Outlook Web Access
        "/remote",
        "/vpn",
        "/citrix",
        "/rdweb",
    ]
    
    # MFA/SSO provider indicators in responses
    MFA_INDICATORS = {
        # Azure AD / Microsoft
        "login.microsoftonline.com": "Microsoft/Azure AD",
        "login.microsoft.com": "Microsoft",
        "login.windows.net": "Azure AD",
        
        # Okta
        "okta.com": "Okta",
        ".oktapreview.com": "Okta",
        
        # Auth0
        "auth0.com": "Auth0",
        
        # Google
        "accounts.google.com": "Google Workspace",
        
        # Other SSO
        "onelogin.com": "OneLogin",
        "pingidentity.com": "Ping Identity",
        "duo.com": "Duo Security",
        "duosecurity.com": "Duo Security",
        
        # Generic MFA keywords
        "two-factor": "MFA",
        "2fa": "MFA",
        "mfa": "MFA",
        "authenticator": "MFA",
        "verification code": "MFA",
        "totp": "MFA",
    }
    
    def __init__(self, timeout: float = 8.0):
        """Initialize admin scanner."""
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
        })
    
    def scan(self, domain: str) -> AdminScanResult:
        """
        Scan a domain for exposed admin pages.
        
        Args:
            domain: Domain to scan (e.g., "cosun.nl")
            
        Returns:
            AdminScanResult with findings
        """
        result = AdminScanResult(domain=domain)
        
        try:
            for path in self.ADMIN_PATHS:
                url = f"https://{domain}{path}"
                result.pages_checked.append(url)
                
                page_info = self._check_admin_page(url)
                
                if page_info:
                    if page_info.get('is_login'):
                        result.login_pages_found.append(page_info)
                    else:
                        result.admin_pages_found.append(page_info)
                    
                    # Check for MFA indicators
                    if page_info.get('mfa_detected'):
                        if page_info['mfa_provider'] not in result.mfa_indicators:
                            result.mfa_indicators.append(page_info['mfa_provider'])
                        if page_info.get('sso_provider'):
                            if page_info['sso_provider'] not in result.sso_providers_detected:
                                result.sso_providers_detected.append(page_info['sso_provider'])
                    else:
                        result.exposed_without_mfa += 1
            
            # Calculate score
            result.score = self._calculate_score(result)
            
            # Generate findings
            self._generate_findings(result)
            
        except Exception as e:
            logger.error(f"Admin scan failed for {domain}: {e}")
            result.error = str(e)
            result.score = 1
            result.findings.append(f"⚠️ Admin scan error: {str(e)[:50]}")
        
        return result
    
    def _check_admin_page(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Check if an admin/login page exists and analyze it.
        Uses HEAD first, then GET if needed.
        """
        try:
            # First try HEAD request (lighter)
            response = self.session.head(url, timeout=self.timeout, allow_redirects=True)
            
            # Check if page exists (200, 401, 403 all indicate something is there)
            if response.status_code not in [200, 401, 403, 302, 301]:
                return None
            
            page_info = {
                'url': url,
                'path': urlparse(url).path,
                'status_code': response.status_code,
                'is_login': False,
                'mfa_detected': False,
                'mfa_provider': None,
                'sso_provider': None,
                'redirect_url': None,
            }
            
            # Check redirect location for SSO indicators
            final_url = response.url
            if final_url != url:
                page_info['redirect_url'] = final_url
                
                for indicator, provider in self.MFA_INDICATORS.items():
                    if indicator in final_url.lower():
                        page_info['mfa_detected'] = True
                        page_info['mfa_provider'] = provider
                        page_info['sso_provider'] = provider
                        break
            
            # If no MFA detected yet and page exists, do a GET to check content
            if not page_info['mfa_detected'] and response.status_code == 200:
                try:
                    get_response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                    content_lower = get_response.text.lower()
                    
                    # Check if it's a login page
                    if any(kw in content_lower for kw in ['login', 'sign in', 'inloggen', 'password', 'wachtwoord', 'username']):
                        page_info['is_login'] = True
                    
                    # Check for MFA indicators in content
                    for indicator, provider in self.MFA_INDICATORS.items():
                        if indicator.lower() in content_lower:
                            page_info['mfa_detected'] = True
                            page_info['mfa_provider'] = provider
                            break
                    
                    # Check response headers for SSO
                    for header_value in get_response.headers.values():
                        for indicator, provider in self.MFA_INDICATORS.items():
                            if indicator in str(header_value).lower():
                                page_info['mfa_detected'] = True
                                page_info['sso_provider'] = provider
                                break
                                
                except requests.exceptions.RequestException:
                    pass
            
            return page_info
            
        except requests.exceptions.RequestException as e:
            logger.debug(f"Could not check {url}: {e}")
            return None
    
    def _calculate_score(self, result: AdminScanResult) -> int:
        """
        Calculate security score for admin exposure.
        
        Score logic:
        - 2: No exposed admin pages OR all have MFA/SSO
        - 1: Some admin pages found but with MFA
        - 0: Admin pages exposed without MFA indicators
        """
        total_found = len(result.admin_pages_found) + len(result.login_pages_found)
        
        if total_found == 0:
            return 2  # No admin pages found (good or well-hidden)
        
        if result.exposed_without_mfa == 0 and result.mfa_indicators:
            return 2  # All pages have MFA
        
        if result.mfa_indicators:
            return 1  # Some MFA detected
        
        if total_found > 0 and result.exposed_without_mfa > 0:
            return 0  # Exposed without MFA
        
        return 1  # Default uncertain
    
    def _generate_findings(self, result: AdminScanResult) -> None:
        """Generate human-readable findings."""
        findings = []
        
        total_found = len(result.admin_pages_found) + len(result.login_pages_found)
        
        if total_found == 0:
            findings.append("✅ No exposed admin/login pages detected")
        else:
            findings.append(f"ℹ️ Found {total_found} admin/login page(s)")
            
            # List found pages
            for page in result.admin_pages_found[:3]:
                status = "🔒" if page.get('mfa_detected') else "⚠️"
                findings.append(f"   {status} {page['path']} (status: {page['status_code']})")
            
            for page in result.login_pages_found[:3]:
                status = "🔒" if page.get('mfa_detected') else "⚠️"
                findings.append(f"   {status} {page['path']} [login] (status: {page['status_code']})")
        
        # MFA/SSO findings
        if result.sso_providers_detected:
            findings.append(f"✅ SSO detected: {', '.join(result.sso_providers_detected)}")
        
        if result.mfa_indicators:
            findings.append(f"✅ MFA indicators: {', '.join(set(result.mfa_indicators))}")
        
        if result.exposed_without_mfa > 0:
            findings.append(f"❌ {result.exposed_without_mfa} page(s) without visible MFA protection")
            findings.append("   → Consider implementing SSO/MFA for all admin access")
        
        result.findings = findings
