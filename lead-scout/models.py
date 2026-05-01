from dataclasses import dataclass


@dataclass
class CompanyInput:
    """Input data for a company to scan."""

    name: str
    domain: str
    sector: str
    employees: int
