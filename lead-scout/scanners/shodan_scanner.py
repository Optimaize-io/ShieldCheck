"""
Shodan Scanner - Internet Exposure Check
Uses the FREE Shodan InternetDB API (no API key required) to check for:
- Open ports
- Known vulnerabilities (CVEs)
- Service banners
"""

import socket
import requests
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ShodanScanResult:
    """Results from Shodan InternetDB scan."""
    domain: str
    ip_address: Optional[str] = None
    ports: List[int] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)
    cpes: List[str] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    risky_ports: List[int] = field(default_factory=list)
    risky_ports_detail: Dict[int, str] = field(default_factory=dict)
    score: int = 2  # Default good score
    findings: List[str] = field(default_factory=list)
    not_indexed: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "ip_address": self.ip_address,
            "ports": self.ports,
            "vulns": self.vulns,
            "cpes": self.cpes,
            "hostnames": self.hostnames,
            "tags": self.tags,
            "risky_ports": self.risky_ports,
            "risky_ports_detail": self.risky_ports_detail,
            "score": self.score,
            "findings": self.findings,
            "not_indexed": self.not_indexed,
            "error": self.error
        }


class ShodanScanner:
    """
    Uses Shodan InternetDB API to check internet-facing exposure.
    This API is FREE and requires no API key.
    
    API docs: https://internetdb.shodan.io/
    """
    
    INTERNETDB_URL = "https://internetdb.shodan.io"
    USER_AGENT = "Polderbase-NIS2-Scout/1.0 (security research)"
    
    # Risky ports and their services
    RISKY_PORTS = {
        21: "FTP - file transfer, often unencrypted",
        22: "SSH - secure but often targeted",
        23: "Telnet - unencrypted remote access (CRITICAL)",
        25: "SMTP - mail server, potential relay",
        53: "DNS - can be used for amplification attacks",
        110: "POP3 - unencrypted email",
        135: "MSRPC - Windows RPC",
        139: "NetBIOS - Windows file sharing",
        143: "IMAP - unencrypted email",
        445: "SMB - Windows file sharing (often exploited)",
        1433: "MSSQL - database server",
        1521: "Oracle DB - database server",
        3306: "MySQL - database server",
        3389: "RDP - Remote Desktop (frequently attacked)",
        5432: "PostgreSQL - database server",
        5900: "VNC - remote desktop (often weak auth)",
        5901: "VNC - remote desktop",
        6379: "Redis - in-memory database",
        8080: "HTTP Proxy - alternative web",
        8443: "HTTPS Alt - alternative secure web",
        27017: "MongoDB - often misconfigured",
    }
    
    # High-risk ports that should always be flagged
    HIGH_RISK_PORTS = {21, 23, 445, 3389, 5900, 27017, 6379}
    
    def __init__(self, timeout: float = 8.0):
        """
        Initialize Shodan scanner.
        
        Args:
            timeout: HTTP request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.USER_AGENT,
            "Accept": "application/json"
        })
    
    def scan(self, domain: str) -> ShodanScanResult:
        """
        Scan a domain using Shodan InternetDB.
        
        Args:
            domain: Domain to scan (e.g., "example.nl")
            
        Returns:
            ShodanScanResult with exposure findings
        """
        result = ShodanScanResult(domain=domain)
        
        try:
            # Resolve domain to IP
            ip = self._resolve_domain(domain)
            if not ip:
                result.error = "Could not resolve domain to IP"
                result.score = 2  # Assume good if we can't check
                result.findings.append("⚠️ Could not resolve domain IP - unable to check Shodan")
                return result
            
            result.ip_address = ip
            
            # Query Shodan InternetDB
            data = self._query_internetdb(ip)
            
            if data is None:
                # 404 = not indexed = likely well-protected
                result.not_indexed = True
                result.score = 2
                result.findings.append("✅ Not indexed in Shodan - low internet exposure")
                return result
            
            # Parse results
            result.ports = data.get("ports", [])
            result.vulns = data.get("vulns", [])
            result.cpes = data.get("cpes", [])
            result.hostnames = data.get("hostnames", [])
            result.tags = data.get("tags", [])
            
            # Identify risky ports
            for port in result.ports:
                if port in self.RISKY_PORTS:
                    result.risky_ports.append(port)
                    result.risky_ports_detail[port] = self.RISKY_PORTS[port]
            
            # Calculate score
            result.score = self._calculate_score(result)
            
            # Generate findings
            self._generate_findings(result)
            
        except Exception as e:
            logger.error(f"Shodan scan failed for {domain}: {e}")
            result.error = str(e)
            result.score = 2  # Assume good on error
            result.findings.append(f"⚠️ Shodan check error: {str(e)[:50]}")
        
        return result
    
    def _resolve_domain(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address."""
        try:
            ip = socket.gethostbyname(domain)
            logger.debug(f"Resolved {domain} to {ip}")
            return ip
        except socket.gaierror as e:
            logger.warning(f"Could not resolve {domain}: {e}")
            return None
    
    def _query_internetdb(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Query Shodan InternetDB API.
        
        Returns:
            API response data, or None if not indexed (404)
        """
        url = f"{self.INTERNETDB_URL}/{ip}"
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 404:
                # Not in database = potentially well-protected
                logger.debug(f"IP {ip} not in Shodan InternetDB")
                return None
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.Timeout:
            logger.warning(f"Shodan API timeout for {ip}")
            raise
        except requests.exceptions.RequestException as e:
            logger.warning(f"Shodan API error for {ip}: {e}")
            raise
    
    def _calculate_score(self, result: ShodanScanResult) -> int:
        """
        Calculate security score based on Shodan findings.
        
        Score logic:
        - Start at 2 (good)
        - >5 CVEs: score = 0
        - Any CVEs: score = 1
        - >2 risky ports from HIGH_RISK set: score -= 1
        """
        score = 2
        
        # Check vulnerabilities
        num_vulns = len(result.vulns)
        if num_vulns > 5:
            score = 0
        elif num_vulns > 0:
            score = min(score, 1)
        
        # Check high-risk ports
        high_risk_count = sum(1 for p in result.risky_ports if p in self.HIGH_RISK_PORTS)
        if high_risk_count > 2:
            score = max(0, score - 1)
        elif high_risk_count > 0:
            score = min(score, 1)
        
        return score
    
    def _generate_findings(self, result: ShodanScanResult) -> None:
        """Generate human-readable findings list."""
        findings = []
        
        # Vulnerability findings
        num_vulns = len(result.vulns)
        if num_vulns > 5:
            findings.append(f"❌ {num_vulns} known CVEs detected - CRITICAL")
            # List first few CVEs
            for cve in result.vulns[:5]:
                findings.append(f"   • {cve}")
            if num_vulns > 5:
                findings.append(f"   • ... and {num_vulns - 5} more")
        elif num_vulns > 0:
            findings.append(f"⚠️ {num_vulns} known CVE(s) detected:")
            for cve in result.vulns[:3]:
                findings.append(f"   • {cve}")
        else:
            findings.append("✅ No known CVEs detected")
        
        # Port findings
        if result.ports:
            findings.append(f"ℹ️ {len(result.ports)} open port(s) detected")
            
            # Flag risky ports
            high_risk_found = []
            for port in result.risky_ports:
                if port in self.HIGH_RISK_PORTS:
                    high_risk_found.append(port)
                    findings.append(f"❌ Port {port} open: {self.RISKY_PORTS[port]}")
            
            # Other risky but less critical
            for port in result.risky_ports:
                if port not in self.HIGH_RISK_PORTS:
                    findings.append(f"⚠️ Port {port} open: {self.RISKY_PORTS[port]}")
        else:
            findings.append("✅ No unexpected open ports")
        
        # Tags
        if result.tags:
            tags_str = ", ".join(result.tags[:5])
            findings.append(f"ℹ️ Shodan tags: {tags_str}")
        
        result.findings = findings
