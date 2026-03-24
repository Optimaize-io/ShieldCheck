"""
DNS Scanner - Email Security Checks
Scans SPF, DMARC, and DKIM records to assess email security posture.
"""

import dns.resolver
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class DNSScanResult:
    """Results from DNS security scan."""
    domain: str
    spf_record: Optional[str] = None
    spf_score: int = 0
    spf_policy: str = "missing"
    dmarc_record: Optional[str] = None
    dmarc_score: int = 0
    dmarc_policy: str = "missing"
    dkim_found: bool = False
    dkim_selector: Optional[str] = None
    dkim_score: int = 0
    total_score: int = 0
    findings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "spf": {
                "record": self.spf_record,
                "score": self.spf_score,
                "policy": self.spf_policy
            },
            "dmarc": {
                "record": self.dmarc_record,
                "score": self.dmarc_score,
                "policy": self.dmarc_policy
            },
            "dkim": {
                "found": self.dkim_found,
                "selector": self.dkim_selector,
                "score": self.dkim_score
            },
            "total_score": self.total_score,
            "findings": self.findings,
            "error": self.error
        }


class DNSScanner:
    """
    Scans DNS records for email security configuration.
    Checks SPF, DMARC, and DKIM to assess email authentication posture.
    """
    
    # Common DKIM selectors used by major email providers
    DKIM_SELECTORS = [
        "google",      # Google Workspace
        "selector1",   # Microsoft 365
        "selector2",   # Microsoft 365
        "default",     # Generic
        "mail",        # Generic
        "k1",          # Mailchimp
        "dkim",        # Generic
        "s1",          # Generic
        "s2",          # Generic
        "mxvault",     # Various
        "protonmail",  # ProtonMail
        "mailjet",     # Mailjet
        "sendgrid",    # SendGrid
        "mandrill",    # Mandrill
        "amazonses",   # AWS SES
    ]
    
    def __init__(self, timeout: float = 8.0):
        """
        Initialize DNS scanner.
        
        Args:
            timeout: DNS query timeout in seconds
        """
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def scan(self, domain: str) -> DNSScanResult:
        """
        Perform complete DNS security scan on a domain.
        
        Args:
            domain: Domain to scan (e.g., "example.nl")
            
        Returns:
            DNSScanResult with all findings
        """
        result = DNSScanResult(domain=domain)
        
        try:
            # Run all checks
            self._check_spf(domain, result)
            self._check_dmarc(domain, result)
            self._check_dkim(domain, result)
            
            # Calculate total score (average of 3 checks, each 0-2)
            avg_score = (result.spf_score + result.dmarc_score + result.dkim_score) / 3
            result.total_score = round(avg_score, 2)
            
            # Generate findings summary
            self._generate_findings(result)
            
        except Exception as e:
            logger.error(f"DNS scan failed for {domain}: {e}")
            result.error = str(e)
        
        return result
    
    def _check_spf(self, domain: str, result: DNSScanResult) -> None:
        """Check SPF record and policy strength."""
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if txt_record.lower().startswith('v=spf1'):
                    result.spf_record = txt_record
                    
                    # Analyze SPF policy
                    txt_lower = txt_record.lower()
                    if '-all' in txt_lower:
                        result.spf_score = 2
                        result.spf_policy = "strict (-all)"
                    elif '~all' in txt_lower:
                        result.spf_score = 1
                        result.spf_policy = "soft (~all)"
                    elif '?all' in txt_lower:
                        result.spf_score = 0
                        result.spf_policy = "neutral (?all)"
                    elif '+all' in txt_lower:
                        result.spf_score = 0
                        result.spf_policy = "open (+all) - DANGEROUS"
                    else:
                        result.spf_score = 1
                        result.spf_policy = "configured (no all)"
                    
                    logger.debug(f"SPF for {domain}: {result.spf_policy}")
                    return
            
            # No SPF record found
            result.spf_score = 0
            result.spf_policy = "missing"
            
        except dns.resolver.NXDOMAIN:
            result.spf_score = 0
            result.spf_policy = "domain not found"
        except dns.resolver.NoAnswer:
            result.spf_score = 0
            result.spf_policy = "no TXT records"
        except dns.resolver.Timeout:
            result.spf_score = 0
            result.spf_policy = "timeout"
        except Exception as e:
            logger.warning(f"SPF check failed for {domain}: {e}")
            result.spf_score = 0
            result.spf_policy = f"error: {str(e)[:50]}"
    
    def _check_dmarc(self, domain: str, result: DNSScanResult) -> None:
        """Check DMARC record and policy."""
        dmarc_domain = f"_dmarc.{domain}"
        
        try:
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if txt_record.lower().startswith('v=dmarc1'):
                    result.dmarc_record = txt_record
                    
                    # Analyze DMARC policy
                    txt_lower = txt_record.lower()
                    if 'p=reject' in txt_lower:
                        result.dmarc_score = 2
                        result.dmarc_policy = "reject"
                    elif 'p=quarantine' in txt_lower:
                        result.dmarc_score = 1
                        result.dmarc_policy = "quarantine"
                    elif 'p=none' in txt_lower:
                        result.dmarc_score = 0
                        result.dmarc_policy = "none (monitoring only)"
                    else:
                        result.dmarc_score = 0
                        result.dmarc_policy = "configured (no policy)"
                    
                    logger.debug(f"DMARC for {domain}: {result.dmarc_policy}")
                    return
            
            result.dmarc_score = 0
            result.dmarc_policy = "missing"
            
        except dns.resolver.NXDOMAIN:
            result.dmarc_score = 0
            result.dmarc_policy = "missing"
        except dns.resolver.NoAnswer:
            result.dmarc_score = 0
            result.dmarc_policy = "missing"
        except dns.resolver.Timeout:
            result.dmarc_score = 0
            result.dmarc_policy = "timeout"
        except Exception as e:
            logger.warning(f"DMARC check failed for {domain}: {e}")
            result.dmarc_score = 0
            result.dmarc_policy = f"error: {str(e)[:50]}"
    
    def _check_dkim(self, domain: str, result: DNSScanResult) -> None:
        """Check for DKIM records using common selectors."""
        for selector in self.DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{domain}"
            
            try:
                answers = self.resolver.resolve(dkim_domain, 'TXT')
                
                for rdata in answers:
                    txt_record = str(rdata).strip('"')
                    if 'v=dkim1' in txt_record.lower() or 'p=' in txt_record:
                        result.dkim_found = True
                        result.dkim_selector = selector
                        result.dkim_score = 2
                        logger.debug(f"DKIM found for {domain} with selector: {selector}")
                        return
                        
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except dns.resolver.Timeout:
                continue
            except Exception:
                continue
        
        # No DKIM found with any selector
        result.dkim_found = False
        result.dkim_score = 0
        logger.debug(f"No DKIM found for {domain}")
    
    def _generate_findings(self, result: DNSScanResult) -> None:
        """Generate human-readable findings list."""
        findings = []
        
        # SPF findings
        if result.spf_score == 0:
            if result.spf_policy == "missing":
                findings.append("❌ No SPF record - email spoofing possible")
            elif result.spf_policy == "open (+all) - DANGEROUS":
                findings.append("❌ SPF allows any sender (+all) - CRITICAL")
            elif result.spf_policy == "neutral (?all)":
                findings.append("⚠️ Weak SPF policy (?all) - spoofing not blocked")
        elif result.spf_score == 1:
            findings.append("⚠️ SPF uses soft fail (~all) - spoofing may succeed")
        else:
            findings.append("✅ Strong SPF policy (-all)")
        
        # DMARC findings
        if result.dmarc_score == 0:
            if result.dmarc_policy == "missing":
                findings.append("❌ No DMARC record - no email authentication enforcement")
            elif result.dmarc_policy == "none (monitoring only)":
                findings.append("⚠️ DMARC in monitoring mode (p=none) - not enforcing")
        elif result.dmarc_score == 1:
            findings.append("⚠️ DMARC quarantine policy - emails may go to spam")
        else:
            findings.append("✅ DMARC reject policy active")
        
        # DKIM findings
        if result.dkim_score == 0:
            findings.append("⚠️ No DKIM record found with common selectors")
        else:
            findings.append(f"✅ DKIM configured (selector: {result.dkim_selector})")
        
        result.findings = findings
