"""
Tech Stack Detection Scanner
Detects web technologies, CMS, and outdated software versions.
"""

import requests
import logging
import re
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class TechStackScanResult:
    """Results from tech stack detection scanning."""
    domain: str
    technologies: List[Dict[str, Any]] = field(default_factory=list)
    outdated_software: List[Dict[str, str]] = field(default_factory=list)
    version_leaks: List[Dict[str, str]] = field(default_factory=list)
    cms_detected: Optional[str] = None
    js_libraries: List[Dict[str, Any]] = field(default_factory=list)
    server_info: Optional[str] = None
    score: int = 2  # Default good score
    findings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "technologies": self.technologies,
            "outdated_software": self.outdated_software,
            "version_leaks": self.version_leaks,
            "cms_detected": self.cms_detected,
            "js_libraries": self.js_libraries,
            "server_info": self.server_info,
            "score": self.score,
            "findings": self.findings,
            "error": self.error
        }


class TechStackScanner:
    """
    Detects web technologies and identifies outdated/vulnerable software.
    """
    
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    # CMS detection patterns (in HTML)
    CMS_PATTERNS = {
        "WordPress": [r'/wp-content/', r'/wp-includes/', r'wp-json', r'wordpress'],
        "Drupal": [r'Drupal\.settings', r'/sites/default/', r'/modules/contrib/'],
        "TYPO3": [r'/typo3/', r'/typo3conf/', r'TYPO3'],
        "Joomla": [r'/media/jui/', r'/components/com_', r'Joomla'],
        "Magento": [r'/static/frontend/', r'Mage\.', r'magento'],
        "Shopify": [r'cdn\.shopify\.com', r'shopify-section'],
        "Wix": [r'wix\.com', r'wixstatic\.com', r'_wix_browser_'],
        "Squarespace": [r'squarespace\.com', r'squarespace-cdn'],
        "Sitecore": [r'/sitecore/', r'sitecore'],
        "Umbraco": [r'/umbraco/', r'umbraco'],
        "Adobe Experience Manager": [r'/content/dam/', r'/etc.clientlibs/', r'/libs/granite/'],
    }
    
    # Known outdated software versions with EOL dates
    OUTDATED_VERSIONS = {
        "PHP": {
            "pattern": r'PHP[/\s]*([\d.]+)',
            "min_version": "8.1",
            "eol_versions": {
                "7.4": "November 2022",
                "7.3": "December 2021",
                "7.2": "November 2020",
                "7.1": "December 2019",
                "7.0": "December 2018",
                "5.6": "December 2018",
            }
        },
        "Apache": {
            "pattern": r'Apache[/\s]*([\d.]+)',
            "min_version": "2.4.50",
            "eol_versions": {}  # Apache doesn't have formal EOL, but old versions have CVEs
        },
        "nginx": {
            "pattern": r'nginx[/\s]*([\d.]+)',
            "min_version": "1.20",
            "eol_versions": {}
        },
        "Microsoft-IIS": {
            "pattern": r'Microsoft-IIS[/\s]*([\d.]+)',
            "min_version": "10.0",
            "eol_versions": {
                "7.0": "January 2020",
                "7.5": "January 2020",
                "8.0": "January 2023",
            }
        },
        "OpenSSL": {
            "pattern": r'OpenSSL[/\s]*([\d.]+[a-z]?)',
            "min_version": "1.1.1",
            "eol_versions": {
                "1.0.2": "December 2019",
                "1.0.1": "December 2016",
            }
        }
    }
    
    # JavaScript library patterns with known vulnerable versions
    JS_LIBRARIES = {
        "jQuery": {
            "pattern": r'jquery[.-]?([\d.]+)(?:\.min)?\.js',
            "version_pattern": r'jQuery\s+v?([\d.]+)',
            "min_safe_version": "3.5.0",
            "cve_note": "< 3.5.0 has XSS vulnerabilities (CVE-2020-11022, CVE-2020-11023)"
        },
        "Angular": {
            "pattern": r'angular[.-]?([\d.]+)(?:\.min)?\.js',
            "version_pattern": r'AngularJS\s+v?([\d.]+)',
            "min_safe_version": "1.8.0",
            "cve_note": "< 1.6.0 has various security issues"
        },
        "Bootstrap": {
            "pattern": r'bootstrap[.-]?([\d.]+)(?:\.min)?\.js',
            "version_pattern": None,
            "min_safe_version": "4.3.1",
            "cve_note": "< 4.3.1 has XSS vulnerability"
        },
        "React": {
            "pattern": r'react[.-]?([\d.]+)(?:\.min)?\.js',
            "version_pattern": r'React\s+v?([\d.]+)',
            "min_safe_version": "16.13.0",
            "cve_note": None  # React is generally safe
        },
        "Vue": {
            "pattern": r'vue[.-]?([\d.]+)(?:\.min)?\.js',
            "version_pattern": r'Vue\.js\s+v?([\d.]+)',
            "min_safe_version": "2.6.0",
            "cve_note": None
        },
        "Lodash": {
            "pattern": r'lodash[.-]?([\d.]+)(?:\.min)?\.js',
            "version_pattern": None,
            "min_safe_version": "4.17.21",
            "cve_note": "< 4.17.21 has prototype pollution (CVE-2021-23337)"
        }
    }
    
    def __init__(self, timeout: float = 10.0):
        """Initialize tech stack scanner."""
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
        })
    
    def scan(self, domain: str, response: Optional[requests.Response] = None,
             html_content: Optional[str] = None) -> TechStackScanResult:
        """
        Detect tech stack from HTTP response.
        
        Args:
            domain: Domain scanned
            response: Optional existing response
            html_content: Optional HTML content
            
        Returns:
            TechStackScanResult with findings
        """
        result = TechStackScanResult(domain=domain)
        
        try:
            # Get response if not provided
            if response is None:
                url = f"https://{domain}"
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                html_content = response.text
            
            # Analyze headers for server info
            self._analyze_headers(response.headers, result)
            
            # Detect CMS from HTML
            if html_content:
                self._detect_cms(html_content, result)
                self._detect_js_libraries(html_content, result)
            
            # Calculate score
            result.score = self._calculate_score(result)
            
            # Generate findings
            self._generate_findings(result)
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Tech stack scan failed for {domain}: {e}")
            result.error = str(e)
            result.score = 1  # Neutral on error
            result.findings.append(f"⚠️ Could not analyze tech stack: {str(e)[:50]}")
        
        return result
    
    def _analyze_headers(self, headers: Dict, result: TechStackScanResult) -> None:
        """Analyze HTTP headers for server/technology info."""
        # Check Server header
        if "Server" in headers:
            server = headers["Server"]
            result.server_info = server
            result.version_leaks.append({
                "header": "Server",
                "value": server
            })
            
            # Check for outdated versions
            self._check_version(server, result)
        
        # Check X-Powered-By
        if "X-Powered-By" in headers:
            powered_by = headers["X-Powered-By"]
            result.version_leaks.append({
                "header": "X-Powered-By",
                "value": powered_by
            })
            self._check_version(powered_by, result)
        
        # Check for other version-leaking headers
        for header in ["X-AspNet-Version", "X-AspNetMvc-Version"]:
            if header in headers:
                result.version_leaks.append({
                    "header": header,
                    "value": headers[header]
                })
    
    def _check_version(self, text: str, result: TechStackScanResult) -> None:
        """Check if text contains outdated software versions."""
        for software, info in self.OUTDATED_VERSIONS.items():
            match = re.search(info["pattern"], text, re.IGNORECASE)
            if match:
                version = match.group(1)
                
                result.technologies.append({
                    "name": software,
                    "version": version,
                    "source": "header"
                })
                
                # Check if EOL
                for eol_version, eol_date in info.get("eol_versions", {}).items():
                    if version.startswith(eol_version):
                        result.outdated_software.append({
                            "software": software,
                            "version": version,
                            "issue": f"End-of-life since {eol_date}",
                            "severity": "HIGH"
                        })
                        break
                else:
                    # Check if below minimum recommended version
                    if self._version_compare(version, info["min_version"]) < 0:
                        result.outdated_software.append({
                            "software": software,
                            "version": version,
                            "issue": f"Below recommended version {info['min_version']}",
                            "severity": "MEDIUM"
                        })
    
    def _version_compare(self, v1: str, v2: str) -> int:
        """Compare two version strings. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
        try:
            def parse_version(v):
                # Remove non-numeric suffixes and split
                v = re.sub(r'[^0-9.]', '', v)
                return [int(x) for x in v.split('.') if x]
            
            v1_parts = parse_version(v1)
            v2_parts = parse_version(v2)
            
            # Pad shorter list
            while len(v1_parts) < len(v2_parts):
                v1_parts.append(0)
            while len(v2_parts) < len(v1_parts):
                v2_parts.append(0)
            
            for i in range(len(v1_parts)):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            return 0
        except:
            return 0  # Can't compare, assume equal
    
    def _detect_cms(self, html: str, result: TechStackScanResult) -> None:
        """Detect CMS from HTML content."""
        html_lower = html.lower()
        
        for cms, patterns in self.CMS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    result.cms_detected = cms
                    result.technologies.append({
                        "name": cms,
                        "version": None,
                        "source": "html"
                    })
                    return  # Only detect first match
    
    def _detect_js_libraries(self, html: str, result: TechStackScanResult) -> None:
        """Detect JavaScript libraries and their versions."""
        for lib_name, lib_info in self.JS_LIBRARIES.items():
            # Try URL pattern first
            match = re.search(lib_info["pattern"], html, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else None
                
                lib_entry = {
                    "name": lib_name,
                    "version": version,
                    "outdated": False,
                    "cve_note": None
                }
                
                if version and lib_info.get("min_safe_version"):
                    if self._version_compare(version, lib_info["min_safe_version"]) < 0:
                        lib_entry["outdated"] = True
                        lib_entry["cve_note"] = lib_info.get("cve_note")
                        
                        result.outdated_software.append({
                            "software": lib_name,
                            "version": version,
                            "issue": lib_info.get("cve_note", f"Below safe version {lib_info['min_safe_version']}"),
                            "severity": "MEDIUM" if lib_info.get("cve_note") else "LOW"
                        })
                
                result.js_libraries.append(lib_entry)
            
            # Also try version pattern in inline scripts
            if lib_info.get("version_pattern"):
                match = re.search(lib_info["version_pattern"], html)
                if match:
                    version = match.group(1)
                    # Only add if not already detected
                    existing = next((l for l in result.js_libraries if l["name"] == lib_name), None)
                    if not existing:
                        result.js_libraries.append({
                            "name": lib_name,
                            "version": version,
                            "outdated": False,
                            "cve_note": None
                        })
    
    def _calculate_score(self, result: TechStackScanResult) -> int:
        """
        Calculate tech stack hygiene score.
        
        Score logic:
        - 2: Modern/hidden tech stack, no issues
        - 1: Some version leaks or minor outdated software
        - 0: Critical outdated software with known CVEs
        """
        has_critical_outdated = any(
            item.get("severity") == "HIGH" 
            for item in result.outdated_software
        )
        has_medium_outdated = any(
            item.get("severity") == "MEDIUM"
            for item in result.outdated_software
        )
        has_version_leaks = len(result.version_leaks) > 0
        
        if has_critical_outdated:
            return 0
        elif has_medium_outdated or (has_version_leaks and len(result.version_leaks) > 1):
            return 1
        else:
            return 2
    
    def _generate_findings(self, result: TechStackScanResult) -> None:
        """Generate human-readable findings."""
        findings = []
        
        # CMS detection
        if result.cms_detected:
            findings.append(f"🔧 CMS Detected: {result.cms_detected}")
        
        # Server info
        if result.server_info:
            findings.append(f"ℹ️ Server: {result.server_info}")
        
        # Version leaks
        if result.version_leaks:
            findings.append(f"⚠️ {len(result.version_leaks)} version leak(s) in headers:")
            for leak in result.version_leaks:
                findings.append(f"   • {leak['header']}: {leak['value']}")
        else:
            findings.append("✅ No version information leaked in headers")
        
        # Outdated software
        if result.outdated_software:
            findings.append(f"❌ {len(result.outdated_software)} outdated/vulnerable software:")
            for item in result.outdated_software:
                severity_emoji = "🔴" if item["severity"] == "HIGH" else "🟡"
                findings.append(f"   {severity_emoji} {item['software']} {item['version']} — {item['issue']}")
        else:
            findings.append("✅ No obviously outdated software detected")
        
        # JS libraries
        if result.js_libraries:
            outdated_js = [l for l in result.js_libraries if l.get("outdated")]
            if outdated_js:
                findings.append(f"⚠️ Outdated JavaScript libraries:")
                for lib in outdated_js:
                    findings.append(f"   • {lib['name']} {lib['version']}")
                    if lib.get("cve_note"):
                        findings.append(f"     {lib['cve_note']}")
        
        result.findings = findings
