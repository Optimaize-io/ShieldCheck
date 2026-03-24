"""
NIS2 Sector Classification
Maps Dutch companies to NIS2 sectors and provides sector-specific information.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class NIS2SectorInfo:
    """Information about a NIS2 sector."""
    sector_id: str
    name_en: str
    name_nl: str
    entity_type: str  # "essential" or "important"
    description: str
    employee_threshold: int  # Minimum employees to be covered
    keywords: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "sector_id": self.sector_id,
            "name_en": self.name_en,
            "name_nl": self.name_nl,
            "entity_type": self.entity_type,
            "description": self.description,
            "employee_threshold": self.employee_threshold,
            "keywords": self.keywords
        }


class NIS2Sectors:
    """
    NIS2 sector classification for Dutch companies.
    
    Based on the Dutch Cyberbeveiligingswet (implementation of NIS2).
    Entity types:
    - Essential entities (essentiële entiteiten): Critical sectors, stricter requirements
    - Important entities (belangrijke entiteiten): Important but less critical
    
    Size thresholds generally:
    - Large: 250+ employees OR €50M+ turnover
    - Medium: 50-249 employees OR €10-50M turnover
    """
    
    # Essential sectors (Annex I of NIS2)
    ESSENTIAL_SECTORS = {
        "energy": NIS2SectorInfo(
            sector_id="energy",
            name_en="Energy",
            name_nl="Energie",
            entity_type="essential",
            description="Electricity, oil, gas, hydrogen, district heating/cooling",
            employee_threshold=50,
            keywords=["energie", "energy", "electricity", "gas", "oil", "netbeheer", 
                     "grid", "power", "stroom", "elektriciteit"]
        ),
        "transport": NIS2SectorInfo(
            sector_id="transport",
            name_en="Transport",
            name_nl="Vervoer",
            entity_type="essential",
            description="Air, rail, water, road transport",
            employee_threshold=50,
            keywords=["transport", "logistics", "shipping", "aviation", "railway",
                     "luchtvaart", "scheepvaart", "spoorwegen", "logistiek"]
        ),
        "banking": NIS2SectorInfo(
            sector_id="banking",
            name_en="Banking",
            name_nl="Bankwezen",
            entity_type="essential",
            description="Credit institutions under CRD",
            employee_threshold=50,
            keywords=["bank", "banking", "credit institution", "kredietinstelling"]
        ),
        "financial_infrastructure": NIS2SectorInfo(
            sector_id="financial_infrastructure",
            name_en="Financial Market Infrastructure",
            name_nl="Financiëlemarktinfrastructuur",
            entity_type="essential",
            description="Trading venues, CCPs, CSDs",
            employee_threshold=50,
            keywords=["trading", "exchange", "clearing", "settlement", "beurs"]
        ),
        "healthcare": NIS2SectorInfo(
            sector_id="healthcare",
            name_en="Healthcare",
            name_nl="Gezondheidszorg",
            entity_type="essential",
            description="Healthcare providers, labs, pharma manufacturers",
            employee_threshold=50,
            keywords=["zorg", "health", "hospital", "ziekenhuis", "kliniek",
                     "pharma", "farmaceutisch", "medical", "medisch"]
        ),
        "drinking_water": NIS2SectorInfo(
            sector_id="drinking_water",
            name_en="Drinking Water",
            name_nl="Drinkwater",
            entity_type="essential",
            description="Drinking water supply and distribution",
            employee_threshold=50,
            keywords=["drinkwater", "drinking water", "waterbedrijf", "waterleiding"]
        ),
        "wastewater": NIS2SectorInfo(
            sector_id="wastewater",
            name_en="Wastewater",
            name_nl="Afvalwater",
            entity_type="essential",
            description="Wastewater collection, treatment, disposal",
            employee_threshold=50,
            keywords=["afvalwater", "wastewater", "sewage", "riool", "waterzuivering"]
        ),
        "digital_infrastructure": NIS2SectorInfo(
            sector_id="digital_infrastructure",
            name_en="Digital Infrastructure",
            name_nl="Digitale Infrastructuur",
            entity_type="essential",
            description="IXPs, DNS, TLD registries, cloud, data centers",
            employee_threshold=50,
            keywords=["datacenter", "hosting", "cloud", "dns", "internet exchange",
                     "telecom", "telecommunications"]
        ),
        "ict_managed_services": NIS2SectorInfo(
            sector_id="ict_managed_services",
            name_en="ICT Service Management",
            name_nl="MSP's/MSSP's",
            entity_type="essential",
            description="Managed service providers, managed security service providers",
            employee_threshold=50,
            keywords=["managed services", "msp", "mssp", "it services", "ict diensten"]
        ),
        "public_administration": NIS2SectorInfo(
            sector_id="public_administration",
            name_en="Public Administration",
            name_nl="Openbaar Bestuur",
            entity_type="essential",
            description="Central governments, regional governments",
            employee_threshold=1,  # No size threshold for government
            keywords=["overheid", "government", "gemeente", "municipality", "ministerie"]
        ),
        "space": NIS2SectorInfo(
            sector_id="space",
            name_en="Space",
            name_nl="Ruimtevaart",
            entity_type="essential",
            description="Operators of ground-based infrastructure",
            employee_threshold=50,
            keywords=["space", "ruimtevaart", "satellite", "satelliet", "aerospace"]
        ),
    }
    
    # Important sectors (Annex II of NIS2)
    IMPORTANT_SECTORS = {
        "postal": NIS2SectorInfo(
            sector_id="postal",
            name_en="Postal and Courier",
            name_nl="Post- en koeriersdiensten",
            entity_type="important",
            description="Postal services, courier services",
            employee_threshold=50,
            keywords=["post", "postal", "courier", "koerier", "pakket", "parcel"]
        ),
        "waste_management": NIS2SectorInfo(
            sector_id="waste_management",
            name_en="Waste Management",
            name_nl="Afvalbeheer",
            entity_type="important",
            description="Waste collection, treatment, recovery, disposal",
            employee_threshold=50,
            keywords=["afval", "waste", "recycling", "afvalverwerking"]
        ),
        "chemicals": NIS2SectorInfo(
            sector_id="chemicals",
            name_en="Chemicals",
            name_nl="Chemie",
            entity_type="important",
            description="Manufacturing, production, distribution of chemicals",
            employee_threshold=50,
            keywords=["chemie", "chemical", "chemisch", "petrochemie"]
        ),
        "food": NIS2SectorInfo(
            sector_id="food",
            name_en="Food Production",
            name_nl="Levensmiddelenproductie",
            entity_type="important",
            description="Food production, processing, distribution",
            employee_threshold=50,
            keywords=["voeding", "food", "agri", "landbouw", "agriculture",
                     "zuivel", "dairy", "vlees", "meat", "feed"]
        ),
        "manufacturing": NIS2SectorInfo(
            sector_id="manufacturing",
            name_en="Manufacturing",
            name_nl="Vervaardiging",
            entity_type="important",
            description="Medical devices, computers, electronics, machinery, motor vehicles",
            employee_threshold=50,
            keywords=["productie", "manufacturing", "fabriek", "factory",
                     "medical devices", "machinery", "automotive"]
        ),
        "digital_providers": NIS2SectorInfo(
            sector_id="digital_providers",
            name_en="Digital Providers",
            name_nl="Digitale aanbieders",
            entity_type="important",
            description="Online marketplaces, search engines, social networks",
            employee_threshold=50,
            keywords=["online platform", "marketplace", "search engine", "social network"]
        ),
        "research": NIS2SectorInfo(
            sector_id="research",
            name_en="Research",
            name_nl="Onderzoek",
            entity_type="important",
            description="Research organizations",
            employee_threshold=50,
            keywords=["research", "onderzoek", "university", "universiteit", "laboratory"]
        ),
    }
    
    def __init__(self):
        """Initialize the NIS2 sectors database."""
        self.all_sectors = {**self.ESSENTIAL_SECTORS, **self.IMPORTANT_SECTORS}
    
    def classify_by_sector_name(self, sector_name: str) -> Optional[NIS2SectorInfo]:
        """
        Classify a company by its stated sector.
        
        Args:
            sector_name: The sector name from input data
            
        Returns:
            Matching NIS2SectorInfo or None
        """
        sector_lower = sector_name.lower()
        
        # Try direct match
        for sector_id, info in self.all_sectors.items():
            if sector_id in sector_lower:
                return info
            if info.name_en.lower() in sector_lower:
                return info
            if info.name_nl.lower() in sector_lower:
                return info
        
        # Try keyword match
        for sector_id, info in self.all_sectors.items():
            for keyword in info.keywords:
                if keyword in sector_lower:
                    return info
        
        return None
    
    def classify_by_keywords(self, found_keywords: Dict[str, List[str]]) -> List[NIS2SectorInfo]:
        """
        Classify a company by detected website keywords.
        
        Args:
            found_keywords: Dict of sector_id -> found keywords
            
        Returns:
            List of matching NIS2SectorInfo objects
        """
        matches = []
        for sector_id, keywords in found_keywords.items():
            if sector_id in self.all_sectors:
                matches.append(self.all_sectors[sector_id])
        return matches
    
    def get_sector(self, sector_id: str) -> Optional[NIS2SectorInfo]:
        """Get sector info by ID."""
        return self.all_sectors.get(sector_id)
    
    def is_essential(self, sector_id: str) -> bool:
        """Check if a sector is classified as essential."""
        return sector_id in self.ESSENTIAL_SECTORS
    
    def is_covered(self, sector_id: str, employee_count: int) -> bool:
        """
        Check if a company is likely covered by NIS2.
        
        Args:
            sector_id: The NIS2 sector ID
            employee_count: Estimated employee count
            
        Returns:
            True if likely covered by NIS2
        """
        sector = self.all_sectors.get(sector_id)
        if not sector:
            return False
        
        return employee_count >= sector.employee_threshold
    
    def get_compliance_priority(self, sector_id: str, employee_count: int) -> str:
        """
        Get compliance priority level.
        
        Returns: "CRITICAL", "HIGH", "MEDIUM", "LOW", or "UNKNOWN"
        """
        sector = self.all_sectors.get(sector_id)
        if not sector:
            return "UNKNOWN"
        
        if not self.is_covered(sector_id, employee_count):
            return "LOW"
        
        if sector.entity_type == "essential":
            if employee_count >= 250:
                return "CRITICAL"
            else:
                return "HIGH"
        else:
            if employee_count >= 250:
                return "HIGH"
            else:
                return "MEDIUM"
    
    def get_all_essential_sectors(self) -> List[NIS2SectorInfo]:
        """Get all essential sector definitions."""
        return list(self.ESSENTIAL_SECTORS.values())
    
    def get_all_important_sectors(self) -> List[NIS2SectorInfo]:
        """Get all important sector definitions."""
        return list(self.IMPORTANT_SECTORS.values())


# Convenience function
def get_nis2_sector_keywords() -> Dict[str, List[str]]:
    """Get all sector keywords for website scanning."""
    sectors = NIS2Sectors()
    return {
        sector_id: info.keywords
        for sector_id, info in sectors.all_sectors.items()
    }
