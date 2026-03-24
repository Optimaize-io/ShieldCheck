"""
SSL/TLS Scanner - Certificate Validation
Checks SSL certificate validity, expiry, and protocol support.
"""

import ssl
import socket
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SSLScanResult:
    """Results from SSL/TLS scan."""
    domain: str
    has_ssl: bool = False
    certificate_valid: bool = False
    issuer: Optional[str] = None
    subject: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    protocol_version: Optional[str] = None
    san_domains: List[str] = field(default_factory=list)
    score: int = 0
    findings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "has_ssl": self.has_ssl,
            "certificate_valid": self.certificate_valid,
            "issuer": self.issuer,
            "subject": self.subject,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "days_until_expiry": self.days_until_expiry,
            "protocol_version": self.protocol_version,
            "san_domains": self.san_domains,
            "score": self.score,
            "findings": self.findings,
            "error": self.error
        }


class SSLScanner:
    """
    Scans SSL/TLS certificate validity and configuration.
    """
    
    def __init__(self, timeout: float = 8.0):
        """
        Initialize SSL scanner.
        
        Args:
            timeout: Connection timeout in seconds
        """
        self.timeout = timeout
    
    def scan(self, domain: str, port: int = 443) -> SSLScanResult:
        """
        Perform SSL/TLS scan on a domain.
        
        Args:
            domain: Domain to scan (e.g., "example.nl")
            port: Port to connect to (default 443)
            
        Returns:
            SSLScanResult with certificate findings
        """
        result = SSLScanResult(domain=domain)
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    result.has_ssl = True
                    result.certificate_valid = True
                    
                    # Get certificate info
                    cert = ssock.getpeercert()
                    
                    # Parse certificate details
                    self._parse_certificate(cert, result)
                    
                    # Get protocol version
                    result.protocol_version = ssock.version()
                    
            # Calculate score
            result.score = self._calculate_score(result)
            
            # Generate findings
            self._generate_findings(result)
            
        except ssl.SSLCertVerificationError as e:
            result.has_ssl = True
            result.certificate_valid = False
            result.error = f"Certificate verification failed: {str(e)[:100]}"
            result.score = 0
            result.findings.append(f"❌ SSL certificate invalid: {str(e)[:80]}")
            
        except ssl.SSLError as e:
            result.has_ssl = False
            result.error = f"SSL error: {str(e)[:100]}"
            result.score = 0
            result.findings.append(f"❌ SSL/TLS error: {str(e)[:80]}")
            
        except socket.timeout:
            result.error = "Connection timeout"
            result.score = 0
            result.findings.append("⚠️ Connection timeout - could not verify SSL")
            
        except ConnectionRefusedError:
            result.error = "Connection refused on port 443"
            result.score = 0
            result.findings.append("⚠️ Port 443 not responding")
            
        except socket.gaierror as e:
            result.error = f"DNS resolution failed: {str(e)}"
            result.score = 0
            result.findings.append("⚠️ Could not resolve domain")
            
        except Exception as e:
            logger.error(f"SSL scan failed for {domain}: {e}")
            result.error = str(e)
            result.score = 0
            result.findings.append(f"⚠️ SSL check error: {str(e)[:50]}")
        
        return result
    
    def _parse_certificate(self, cert: Dict[str, Any], result: SSLScanResult) -> None:
        """Parse certificate details into result object."""
        
        # Get issuer
        issuer = cert.get('issuer', ())
        if issuer:
            issuer_dict = {}
            for item in issuer:
                if item:
                    key, value = item[0]
                    issuer_dict[key] = value
            result.issuer = issuer_dict.get('organizationName', 
                                           issuer_dict.get('commonName', 'Unknown'))
        
        # Get subject
        subject = cert.get('subject', ())
        if subject:
            subject_dict = {}
            for item in subject:
                if item:
                    key, value = item[0]
                    subject_dict[key] = value
            result.subject = subject_dict.get('commonName', 'Unknown')
        
        # Get validity dates
        not_before = cert.get('notBefore')
        not_after = cert.get('notAfter')
        
        if not_before:
            result.not_before = self._parse_date(not_before)
        
        if not_after:
            result.not_after = self._parse_date(not_after)
            
            # Calculate days until expiry
            if result.not_after:
                now = datetime.now(timezone.utc)
                delta = result.not_after - now
                result.days_until_expiry = delta.days
        
        # Get SAN domains
        san = cert.get('subjectAltName', ())
        result.san_domains = [name for (type_, name) in san if type_ == 'DNS']
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse SSL certificate date string."""
        try:
            # SSL dates are in format: "Jan 15 00:00:00 2025 GMT"
            dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            try:
                # Try alternative format
                dt = datetime.strptime(date_str, "%b  %d %H:%M:%S %Y %Z")
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                logger.warning(f"Could not parse date: {date_str}")
                return None
    
    def _calculate_score(self, result: SSLScanResult) -> int:
        """
        Calculate SSL security score.
        
        Score logic:
        - Invalid/no certificate: 0
        - Expiring within 30 days: 0
        - Expiring within 30-90 days: 1
        - Valid with 90+ days: 2
        
        Protocol bonuses/penalties:
        - TLSv1.3: +0 (already at max)
        - TLSv1.2: 0
        - TLSv1.1 or lower: -1
        """
        if not result.certificate_valid:
            return 0
        
        score = 2  # Start with good score
        
        # Check expiry
        if result.days_until_expiry is not None:
            if result.days_until_expiry < 0:
                # Already expired!
                score = 0
            elif result.days_until_expiry < 30:
                score = 0
            elif result.days_until_expiry < 90:
                score = 1
        
        # Check protocol version
        if result.protocol_version:
            version = result.protocol_version.lower()
            if 'tlsv1.0' in version or 'tlsv1.1' in version or 'sslv' in version:
                score = max(0, score - 1)
        
        return score
    
    def _generate_findings(self, result: SSLScanResult) -> None:
        """Generate human-readable findings list."""
        findings = []
        
        if not result.has_ssl:
            findings.append("❌ No SSL/TLS connection possible")
            result.findings = findings
            return
        
        if not result.certificate_valid:
            findings.append("❌ SSL certificate is invalid or untrusted")
            result.findings = findings
            return
        
        # Certificate validity
        findings.append("✅ SSL certificate is valid and trusted")
        
        # Issuer
        if result.issuer:
            findings.append(f"ℹ️ Issued by: {result.issuer}")
        
        # Expiry
        if result.days_until_expiry is not None:
            if result.days_until_expiry < 0:
                findings.append(f"❌ Certificate EXPIRED {abs(result.days_until_expiry)} days ago!")
            elif result.days_until_expiry < 30:
                findings.append(f"❌ Certificate expires in {result.days_until_expiry} days - URGENT")
            elif result.days_until_expiry < 90:
                findings.append(f"⚠️ Certificate expires in {result.days_until_expiry} days")
            else:
                findings.append(f"✅ Certificate valid for {result.days_until_expiry} days")
        
        # Protocol version
        if result.protocol_version:
            version = result.protocol_version
            if 'TLSv1.3' in version:
                findings.append(f"✅ Using modern protocol: {version}")
            elif 'TLSv1.2' in version:
                findings.append(f"✅ Using secure protocol: {version}")
            elif 'TLSv1.1' in version or 'TLSv1.0' in version:
                findings.append(f"⚠️ Using outdated protocol: {version}")
            else:
                findings.append(f"ℹ️ Protocol: {version}")
        
        result.findings = findings
