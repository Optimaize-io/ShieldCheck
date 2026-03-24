"""
Website Scanner - Content Analysis
Fetches website content and analyzes for security keywords,
NIS2 mentions, and sector indicators.
"""

import requests
import logging
import re
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass, field
from bs4 import BeautifulSoup
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


@dataclass
class WebsiteScanResult:
    """Results from website content scan."""
    domain: str
    pages_checked: List[str] = field(default_factory=list)
    pages_found: List[str] = field(default_factory=list)
    security_keywords_found: List[str] = field(default_factory=list)
    nis2_keywords_found: List[str] = field(default_factory=list)
    sector_indicators: Dict[str, List[str]] = field(default_factory=dict)
    has_security_page: bool = False
    has_privacy_page: bool = False
    security_communication_score: int = 0
    nis2_readiness_score: int = 0
    total_score: int = 0
    findings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "pages_checked": self.pages_checked,
            "pages_found": self.pages_found,
            "security_keywords_found": self.security_keywords_found,
            "nis2_keywords_found": self.nis2_keywords_found,
            "sector_indicators": self.sector_indicators,
            "has_security_page": self.has_security_page,
            "has_privacy_page": self.has_privacy_page,
            "security_communication_score": self.security_communication_score,
            "nis2_readiness_score": self.nis2_readiness_score,
            "total_score": self.total_score,
            "findings": self.findings,
            "error": self.error
        }


class WebsiteScanner:
    """
    Scans website content for security keywords and NIS2 awareness.
    """
    
    USER_AGENT = "Polderbase-NIS2-Scout/1.0 (security research)"
    
    # Pages to scan (in addition to homepage)
    PAGES_TO_CHECK = [
        "/",
        "/security",
        "/beveiliging",
        "/privacy",
        "/privacy-policy",
        "/privacybeleid",
        "/compliance",
        "/about",
        "/about-us",
        "/over-ons",
        "/about/security",
        "/en/security",
        "/nl/security",
        "/corporate",
        "/company",
    ]
    
    # Security-related keywords that indicate awareness
    SECURITY_KEYWORDS = [
        "iso 27001",
        "iso27001",
        "iso-27001",
        "nis2",
        "nis 2",
        "cybersecurity",
        "cyber security",
        "cyberbeveilig",  # Dutch: cyber security
        "informatiebeveiliging",  # Dutch: information security
        "information security",
        "ciso",
        "chief information security",
        "security officer",
        "soc",
        "security operations",
        "pentest",
        "penetration test",
        "penetratietest",
        "gdpr",
        "avg",  # Dutch GDPR
        "dpia",
        "privacy impact",
        "incident response",
        "zero trust",
        "siem",
        "vulnerability",
        "kwetsbaarheid",  # Dutch: vulnerability
        "compliance",
        "risicomanagement",  # Dutch: risk management
        "risk management",
        "beveiligingsbeleid",  # Dutch: security policy
        "security policy",
        "mfa",
        "multi-factor",
        "twee-factor",  # Dutch: two-factor
        "two-factor",
        "soc 2",
        "soc2",
        "audit",
        "certified",
        "gecertificeerd",  # Dutch: certified
        "dnb",  # Dutch Central Bank (financial regulation)
        "afm",  # Dutch Financial Markets Authority
        "toezichthouder",  # Dutch: regulator
        "encryptie",  # Dutch: encryption
        "encryption",
        "backup",
        "disaster recovery",
        "business continuity",
        "bc/dr",
        "bcp",
    ]
    
    # NIS2-specific keywords (higher weight)
    NIS2_KEYWORDS = [
        "nis2",
        "nis 2",
        "nis-2",
        "cyberbeveiligingswet",  # Dutch NIS2 implementation
        "cbw",
        "network and information security",
        "netwerk- en informatiebeveiliging",
        "essential entities",
        "important entities",
        "essentiële entiteiten",
        "belangrijke entiteiten",
        "kritis",  # Critical infrastructure
        "vitale infrastructuur",  # Dutch: vital infrastructure
        "critical infrastructure",
    ]
    
    # Sector indicators for NIS2 categorization
    SECTOR_INDICATORS = {
        "energy": [
            "energie", "energy", "stroom", "electricity", "elektriciteit",
            "gas", "oil", "olie", "petroleum", "netbeheer", "grid operator",
            "power plant", "energiecentrale", "renewable", "duurzame energie",
            "solar", "wind", "zonne-energie", "windenergie"
        ],
        "transport": [
            "transport", "logistiek", "logistics", "shipping", "scheepvaart",
            "aviation", "luchtvaart", "railway", "spoorwegen", "freight",
            "vracht", "haven", "port", "airport", "luchthaven", "cargo",
            "supply chain", "distributie", "distribution"
        ],
        "banking": [
            "bank", "banking", "financ", "financial", "investment",
            "belegging", "asset management", "vermogensbeheer", "lending",
            "krediet", "mortgage", "hypotheek", "retail bank", "private bank"
        ],
        "financial_infrastructure": [
            "betaal", "payment", "clearing", "settlement", "trading platform",
            "beurs", "exchange", "stock", "securities", "effecten"
        ],
        "healthcare": [
            "zorg", "health", "healthcare", "medisch", "medical",
            "ziekenhuis", "hospital", "kliniek", "clinic", "pharma",
            "farmaceutisch", "pharmaceutical", "patient", "patiënt",
            "doctor", "arts", "nursing", "verpleging", "ggz",
            "mental health", "thuiszorg", "home care"
        ],
        "drinking_water": [
            "drinkwater", "drinking water", "waterbedrijf", "water company",
            "waterleiding", "waternet", "vitens", "evides", "brabant water"
        ],
        "wastewater": [
            "afvalwater", "wastewater", "rioolwater", "sewage",
            "waterzuivering", "water treatment", "waterschap"
        ],
        "digital_infrastructure": [
            "datacenter", "data center", "hosting", "cloud",
            "colocation", "internet exchange", "ix", "dns",
            "domain name", "cdn", "content delivery", "isp",
            "internet provider", "telecom", "telecommunications"
        ],
        "ict_managed_services": [
            "managed services", "msp", "mssp", "it services",
            "ict diensten", "outsourcing", "it beheer", "it management",
            "security services", "soc as a service"
        ],
        "public_administration": [
            "gemeente", "municipality", "overheid", "government",
            "provincie", "province", "ministerie", "ministry",
            "rijksoverheid", "central government", "publieke sector",
            "public sector"
        ],
        "space": [
            "space", "ruimtevaart", "satellite", "satelliet",
            "aerospace", "esa", "rocket", "launch"
        ],
        "postal": [
            "post", "postal", "courier", "koerier", "pakket",
            "parcel", "bezorging", "delivery", "logistics"
        ],
        "waste_management": [
            "afval", "waste", "recycling", "afvalverwerking",
            "waste management", "vuilnis", "garbage", "refuse"
        ],
        "chemicals": [
            "chemie", "chemical", "chemisch", "petrochemie",
            "petrochemical", "refinery", "raffinaderij"
        ],
        "food": [
            "voeding", "food", "agri", "landbouw", "agriculture",
            "farming", "veeteelt", "livestock", "food production",
            "voedselproductie", "zuivel", "dairy", "vlees", "meat",
            "beverage", "drank", "feed", "voer", "retail food",
            "supermarkt", "supermarket"
        ],
        "manufacturing": [
            "productie", "manufacturing", "fabriek", "factory",
            "industrie", "industrial", "machine", "equipment",
            "apparatuur", "medical devices", "medische apparatuur",
            "automotive", "motor vehicle", "electronics", "elektronica"
        ],
        "research": [
            "research", "onderzoek", "r&d", "laboratory", "laboratorium",
            "university", "universiteit", "scientific", "wetenschappelijk"
        ],
    }
    
    def __init__(self, timeout: float = 8.0):
        """
        Initialize website scanner.
        
        Args:
            timeout: HTTP request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "nl-NL,nl;q=0.9,en;q=0.8",
        })
    
    def scan(self, domain: str) -> WebsiteScanResult:
        """
        Perform website content scan.
        
        Args:
            domain: Domain to scan (e.g., "example.nl")
            
        Returns:
            WebsiteScanResult with content analysis
        """
        result = WebsiteScanResult(domain=domain)
        
        try:
            # Collect all text content from pages
            all_text = ""
            base_url = f"https://{domain}"
            
            for page_path in self.PAGES_TO_CHECK:
                url = urljoin(base_url, page_path)
                result.pages_checked.append(url)
                
                content = self._fetch_page(url)
                if content:
                    result.pages_found.append(url)
                    all_text += " " + content
                    
                    # Check for dedicated security/privacy pages
                    if any(x in page_path for x in ['/security', '/beveiliging']):
                        result.has_security_page = True
                    if any(x in page_path for x in ['/privacy']):
                        result.has_privacy_page = True
            
            if not all_text.strip():
                result.error = "Could not fetch any pages"
                result.findings.append("⚠️ Could not access website content")
                return result
            
            # Analyze content
            all_text_lower = all_text.lower()
            
            # Find security keywords
            result.security_keywords_found = self._find_keywords(
                all_text_lower, self.SECURITY_KEYWORDS
            )
            
            # Find NIS2 keywords
            result.nis2_keywords_found = self._find_keywords(
                all_text_lower, self.NIS2_KEYWORDS
            )
            
            # Find sector indicators
            result.sector_indicators = self._find_sector_indicators(all_text_lower)
            
            # Calculate scores
            result.security_communication_score = self._score_security_communication(result)
            result.nis2_readiness_score = self._score_nis2_readiness(result)
            result.total_score = round(
                (result.security_communication_score + result.nis2_readiness_score) / 2, 2
            )
            
            # Generate findings
            self._generate_findings(result)
            
        except Exception as e:
            logger.error(f"Website scan failed for {domain}: {e}")
            result.error = str(e)
            result.findings.append(f"⚠️ Website scan error: {str(e)[:50]}")
        
        return result
    
    def _fetch_page(self, url: str) -> Optional[str]:
        """
        Fetch a page and extract text content.
        
        Returns:
            Extracted text content, or None if page not accessible
        """
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            if response.status_code != 200:
                return None
            
            # Parse HTML and extract text
            soup = BeautifulSoup(response.text, 'lxml')
            
            # Remove script and style elements
            for script in soup(["script", "style", "nav", "footer", "header"]):
                script.decompose()
            
            # Get text
            text = soup.get_text(separator=' ', strip=True)
            
            # Clean up whitespace
            text = re.sub(r'\s+', ' ', text)
            
            return text
            
        except requests.exceptions.RequestException:
            return None
        except Exception as e:
            logger.debug(f"Error fetching {url}: {e}")
            return None
    
    def _find_keywords(self, text: str, keywords: List[str]) -> List[str]:
        """Find which keywords appear in the text."""
        found = []
        for keyword in keywords:
            if keyword in text:
                found.append(keyword)
        return found
    
    def _find_sector_indicators(self, text: str) -> Dict[str, List[str]]:
        """Find sector indicators in text."""
        found_sectors = {}
        
        for sector, indicators in self.SECTOR_INDICATORS.items():
            found_indicators = []
            for indicator in indicators:
                if indicator in text:
                    found_indicators.append(indicator)
            
            if found_indicators:
                found_sectors[sector] = found_indicators
        
        return found_sectors
    
    def _score_security_communication(self, result: WebsiteScanResult) -> int:
        """
        Score security communication (0-2).
        
        - Dedicated security page or 5+ keywords: 2
        - 2+ keywords: 1
        - Less: 0
        """
        num_keywords = len(result.security_keywords_found)
        
        if result.has_security_page or num_keywords >= 5:
            return 2
        elif num_keywords >= 2:
            return 1
        else:
            return 0
    
    def _score_nis2_readiness(self, result: WebsiteScanResult) -> int:
        """
        Score NIS2 readiness (0-2).
        
        - Explicit NIS2 mention: 2
        - ISO 27001 mention: 1
        - Neither: 0
        """
        if result.nis2_keywords_found:
            return 2
        
        if "iso 27001" in result.security_keywords_found or \
           "iso27001" in result.security_keywords_found or \
           "iso-27001" in result.security_keywords_found:
            return 1
        
        return 0
    
    def _generate_findings(self, result: WebsiteScanResult) -> None:
        """Generate human-readable findings list."""
        findings = []
        
        # Pages found
        found_count = len(result.pages_found)
        checked_count = len(result.pages_checked)
        findings.append(f"ℹ️ Scanned {found_count}/{checked_count} pages successfully")
        
        # Security page
        if result.has_security_page:
            findings.append("✅ Has dedicated security/beveiliging page")
        else:
            findings.append("⚠️ No dedicated security page found")
        
        # Security keywords
        num_keywords = len(result.security_keywords_found)
        if num_keywords >= 5:
            findings.append(f"✅ Strong security communication ({num_keywords} keywords found)")
            # Show some examples
            examples = result.security_keywords_found[:5]
            findings.append(f"   Keywords: {', '.join(examples)}")
        elif num_keywords >= 2:
            findings.append(f"⚠️ Some security communication ({num_keywords} keywords)")
            findings.append(f"   Keywords: {', '.join(result.security_keywords_found)}")
        else:
            findings.append("❌ Minimal security communication on website")
        
        # NIS2 readiness
        if result.nis2_keywords_found:
            findings.append("✅ NIS2/Cyberbeveiligingswet mentioned on website")
            findings.append(f"   Found: {', '.join(result.nis2_keywords_found[:3])}")
        elif "iso 27001" in result.security_keywords_found:
            findings.append("⚠️ ISO 27001 mentioned but no NIS2 reference")
        else:
            findings.append("❌ No NIS2 or compliance framework mentioned")
        
        # Sector indicators
        if result.sector_indicators:
            sectors = list(result.sector_indicators.keys())
            findings.append(f"ℹ️ Detected sectors: {', '.join(sectors)}")
        
        result.findings = findings
