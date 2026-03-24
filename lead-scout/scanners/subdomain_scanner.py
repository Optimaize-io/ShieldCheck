"""
Subdomain Discovery Scanner (crt.sh)
Discovers subdomains via Certificate Transparency logs.
"""

import requests
import logging
import re
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SubdomainScanResult:
    """Results from subdomain discovery scanning."""
    domain: str
    subdomains_found: List[str] = field(default_factory=list)
    risky_subdomains: List[Dict[str, str]] = field(default_factory=list)
    neutral_subdomains: List[str] = field(default_factory=list)
    total_count: int = 0
    risky_count: int = 0
    score: int = 2  # Default good score
    findings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "subdomains_found": self.subdomains_found,
            "risky_subdomains": self.risky_subdomains,
            "neutral_subdomains": self.neutral_subdomains,
            "total_count": self.total_count,
            "risky_count": self.risky_count,
            "score": self.score,
            "findings": self.findings,
            "error": self.error
        }


class SubdomainScanner:
    """
    Discovers subdomains using Certificate Transparency logs (crt.sh).
    Categorizes them as risky or neutral.
    """
    
    CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
    
    # Risky subdomain patterns with descriptions
    RISKY_PATTERNS = {
        r'^vpn\.': "VPN gateway - potential entry point",
        r'^staging\.': "Staging environment - may lack production security",
        r'^test\.': "Test environment - likely contains test data",
        r'^dev\.': "Development environment - may be unpatched",
        r'^admin\.': "Admin portal - high-value target",
        r'^owa\.': "Outlook Web Access - email gateway",
        r'^ftp\.': "FTP server - legacy protocol",
        r'^old\.': "Legacy system - likely unmaintained",
        r'^legacy\.': "Legacy system - likely unmaintained",
        r'^ilo\.': "HP iLO - server management interface",
        r'^idrac\.': "Dell iDRAC - server management interface",
        r'^portal\.': "Portal - may expose internal systems",
        r'^intranet\.': "Intranet - internal systems exposed",
        r'^mail\.': "Mail server - common attack target",
        r'^webmail\.': "Webmail - authentication target",
        r'^remote\.': "Remote access - VPN/RDP gateway",
        r'^citrix\.': "Citrix gateway - remote access",
        r'^rdp\.': "RDP gateway - remote desktop",
        r'^api\.': "API endpoint - may expose data",
        r'^beta\.': "Beta environment - may be unstable",
        r'^uat\.': "UAT environment - user acceptance testing",
        r'^preprod\.': "Pre-production - may mirror prod data",
        r'^backup\.': "Backup system - sensitive data",
        r'^db\.': "Database server - should not be public",
        r'^mysql\.': "MySQL server - should not be public",
        r'^postgres\.': "PostgreSQL server - should not be public",
        r'^jenkins\.': "Jenkins CI - build system exposed",
        r'^gitlab\.': "GitLab - source code may be exposed",
        r'^jira\.': "Jira - project management exposed",
    }
    
    # Neutral/expected subdomains
    NEUTRAL_PATTERNS = [
        r'^www\.', r'^cdn\.', r'^static\.', r'^assets\.',
        r'^blog\.', r'^docs\.', r'^help\.', r'^support\.',
        r'^shop\.', r'^store\.', r'^careers\.', r'^jobs\.',
        r'^news\.', r'^investor', r'^ir\.', r'^press\.',
    ]
    
    def __init__(self, timeout: float = 20.0):
        """Initialize subdomain scanner with longer timeout for crt.sh."""
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
        })
        # Compile patterns
        self.risky_re = {re.compile(p, re.IGNORECASE): desc 
                        for p, desc in self.RISKY_PATTERNS.items()}
        self.neutral_re = [re.compile(p, re.IGNORECASE) for p in self.NEUTRAL_PATTERNS]
    
    def scan(self, domain: str) -> SubdomainScanResult:
        """
        Discover subdomains using crt.sh Certificate Transparency logs.
        
        Args:
            domain: Domain to scan (e.g., "example.nl")
            
        Returns:
            SubdomainScanResult with findings
        """
        result = SubdomainScanResult(domain=domain)
        
        try:
            url = self.CRT_SH_URL.format(domain=domain)
            logger.info(f"Querying crt.sh for {domain}...")
            
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code != 200:
                result.error = f"crt.sh returned status {response.status_code}"
                result.score = 1  # Neutral on error
                result.findings.append(f"⚠️ Could not query crt.sh: {result.error}")
                return result
            
            try:
                certs = response.json()
            except Exception:
                # Sometimes crt.sh returns empty or invalid JSON
                result.error = "crt.sh returned invalid JSON"
                result.score = 1
                result.findings.append("⚠️ crt.sh returned no data (may not have certificates)")
                return result
            
            if not certs:
                result.findings.append("ℹ️ No certificates found in CT logs")
                result.score = 2
                return result
            
            # Extract unique subdomains
            subdomains = self._extract_subdomains(certs, domain)
            result.subdomains_found = sorted(subdomains)
            result.total_count = len(subdomains)
            
            # Categorize subdomains
            self._categorize_subdomains(subdomains, domain, result)
            
            result.risky_count = len(result.risky_subdomains)
            
            # Calculate score
            result.score = self._calculate_score(result)
            
            # Generate findings
            self._generate_findings(result)
            
        except requests.exceptions.Timeout:
            logger.warning(f"crt.sh timeout for {domain}")
            result.error = "crt.sh timeout (service may be slow)"
            result.score = 1  # Neutral on timeout
            result.findings.append("⚠️ crt.sh request timed out - skipped")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Subdomain scan failed for {domain}: {e}")
            result.error = str(e)
            result.score = 1  # Neutral on error
            result.findings.append(f"⚠️ Could not query crt.sh: {str(e)[:50]}")
        
        return result
    
    def _extract_subdomains(self, certs: List[Dict], domain: str) -> Set[str]:
        """Extract unique subdomains from certificate data."""
        subdomains = set()
        domain_lower = domain.lower()
        
        for cert in certs:
            # Get name_value which contains the domain(s)
            name_value = cert.get("name_value", "")
            
            # Split by newline (crt.sh returns multiple names per line sometimes)
            names = name_value.replace("\n", " ").split()
            
            for name in names:
                name = name.lower().strip()
                
                # Remove wildcard prefix
                if name.startswith("*."):
                    name = name[2:]
                
                # Only include subdomains of our target domain
                if name.endswith(f".{domain_lower}") or name == domain_lower:
                    if name != domain_lower:  # Exclude the main domain itself
                        subdomains.add(name)
        
        return subdomains
    
    def _categorize_subdomains(self, subdomains: Set[str], domain: str, result: SubdomainScanResult) -> None:
        """Categorize subdomains as risky or neutral."""
        domain_lower = domain.lower()
        
        for subdomain in subdomains:
            # Get the subdomain prefix (e.g., "staging" from "staging.example.nl")
            prefix = subdomain.replace(f".{domain_lower}", "")
            prefix_with_dot = prefix.split(".")[0] + "."  # Handle multi-level like "staging.api.example.nl"
            
            is_risky = False
            risk_reason = None
            
            for pattern, description in self.risky_re.items():
                if pattern.match(prefix_with_dot) or pattern.match(prefix + "."):
                    is_risky = True
                    risk_reason = description
                    break
            
            if is_risky:
                result.risky_subdomains.append({
                    "subdomain": subdomain,
                    "reason": risk_reason
                })
            else:
                # Check if it's a known neutral pattern
                is_neutral = False
                for pattern in self.neutral_re:
                    if pattern.match(prefix_with_dot):
                        is_neutral = True
                        break
                result.neutral_subdomains.append(subdomain)
    
    def _calculate_score(self, result: SubdomainScanResult) -> int:
        """
        Calculate attack surface score.
        
        Score logic:
        - 2: 0-2 risky subdomains
        - 1: 3-5 risky subdomains
        - 0: 6+ risky subdomains
        """
        risky_count = len(result.risky_subdomains)
        
        if risky_count <= 2:
            return 2
        elif risky_count <= 5:
            return 1
        else:
            return 0
    
    def _generate_findings(self, result: SubdomainScanResult) -> None:
        """Generate human-readable findings."""
        findings = []
        
        findings.append(f"🔍 Found {result.total_count} subdomain(s) via Certificate Transparency")
        
        if result.risky_subdomains:
            findings.append(f"⚠️ {result.risky_count} potentially risky subdomain(s):")
            for item in result.risky_subdomains[:10]:  # Limit output
                findings.append(f"   • {item['subdomain']} — {item['reason']}")
            if len(result.risky_subdomains) > 10:
                findings.append(f"   ... and {len(result.risky_subdomains) - 10} more")
        else:
            findings.append("✅ No obviously risky subdomains detected")
        
        if result.neutral_subdomains:
            findings.append(f"ℹ️ {len(result.neutral_subdomains)} standard subdomain(s): " + 
                          ", ".join(result.neutral_subdomains[:5]))
            if len(result.neutral_subdomains) > 5:
                findings.append(f"   ... and {len(result.neutral_subdomains) - 5} more")
        
        result.findings = findings
