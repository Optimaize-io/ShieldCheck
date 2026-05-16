#!/usr/bin/env python3
"""
Lead Scout - NIS2 OSINT Scanner for Nomios
Main CLI entry point.
"""

import argparse
import csv
import json
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).parent))

from assessment_service import AssessmentService
from models import CompanyInput
from scoring.scorer import LeadScore, LeadScorer


LOG_FILE = Path(__file__).parent / "output" / "scout.log"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

log_format = "%(asctime)s - %(levelname)s - %(name)s - %(message)s"
console_format = "%(asctime)s - %(levelname)s - %(message)s"

root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)

if not any(
    isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler)
    for handler in root_logger.handlers
):
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(console_format, datefmt="%H:%M:%S"))
    root_logger.addHandler(console_handler)

if not any(
    isinstance(handler, logging.FileHandler) and Path(getattr(handler, "baseFilename", "")) == LOG_FILE
    for handler in root_logger.handlers
):
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(log_format, datefmt="%Y-%m-%d %H:%M:%S"))
    root_logger.addHandler(file_handler)

logger = logging.getLogger(__name__)


def _strip_lead_irrelevant_dimensions(lead: LeadScore) -> LeadScore:
    """Remove dimensions that are not useful for lead-generation output."""

    lead.nis2_readiness = None
    lead.nis2_sector = None
    lead.nis2_entity_type = None
    lead.nis2_covered = False
    lead.compliance_priority = "UNKNOWN"
    lead.security_communication = None
    lead.security_governance = None
    lead.security_hiring = None

    def keep_text(value: str) -> bool:
        text = (value or "").lower()
        blocked_terms = [
            "nis2",
            "cyberbeveiligingswet",
            "security communication",
            "security messaging",
            "dedicated security page",
            "security governance",
            "security leadership",
            "ciso",
            "security hiring",
            "security role",
            "security jobs",
            "jobs page",
            "careers/jobs page",
        ]
        return not any(term in text for term in blocked_terms)

    lead.key_gaps = [item for item in lead.key_gaps if keep_text(item)]
    lead.sales_angles = [item for item in lead.sales_angles if keep_text(item)]
    lead.key_gaps_detailed = [
        item
        for item in lead.key_gaps_detailed
        if keep_text(item.get("title", ""))
        and keep_text(item.get("finding", ""))
        and keep_text(item.get("description", ""))
        and keep_text(item.get("impact", ""))
    ]

    if lead.management_summary and not keep_text(lead.management_summary):
        lead.management_summary = ""

    dimensions = [
        lead.email_security,
        lead.technical_hygiene,
        lead.tls_certificate,
        lead.http_headers,
        lead.cookie_compliance,
        lead.attack_surface,
        lead.tech_stack,
        lead.admin_panel,
    ]
    analyzed_dimensions = [d for d in dimensions if d and d.analyzed]
    lead.total_score = float(sum(d.score for d in analyzed_dimensions))
    lead.max_score = float(sum(d.max_score for d in analyzed_dimensions))
    lead.tier = LeadScorer()._determine_tier(lead.total_score, lead.max_score)
    return lead


class LeadScout:
    """CLI-friendly wrapper over the shared assessment service."""

    def __init__(
        self,
        timeout: float = 8.0,
        verbose: bool = False,
        incremental_save_path: Optional[str] = None,
    ):
        self.timeout = timeout
        self.verbose = verbose
        self.incremental_save_path = incremental_save_path or "output/.scan_progress.json"
        self.assessment_service = AssessmentService(timeout=timeout, verbose=verbose)

    def _save_incremental(self, results: List[LeadScore], scanned_domains: List[str]) -> None:
        try:
            progress_data = {
                "scanned_domains": scanned_domains,
                "results": [lead.to_dict() for lead in results],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
            Path(self.incremental_save_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.incremental_save_path, "w", encoding="utf-8") as handle:
                json.dump(progress_data, handle, indent=2, ensure_ascii=False)
        except Exception as exc:
            logger.warning("Failed to save incremental progress: %s", exc)

    def _load_incremental(self) -> tuple:
        try:
            if Path(self.incremental_save_path).exists():
                with open(self.incremental_save_path, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
                return data.get("scanned_domains", []), data.get("results", [])
        except Exception as exc:
            logger.warning("Could not load incremental progress: %s", exc)
        return [], []

    def _clear_incremental(self) -> None:
        try:
            if Path(self.incremental_save_path).exists():
                Path(self.incremental_save_path).unlink()
        except Exception as exc:
            logger.warning("Could not remove incremental file: %s", exc)

    def scan_company(self, company: CompanyInput) -> LeadScore:
        lead = self.assessment_service.scan_company(company)
        return _strip_lead_irrelevant_dimensions(lead)

    def scan_companies(
        self,
        companies: List[CompanyInput],
        max_workers: int = 1,
        delay: float = 1.0,
        resume: bool = True,
    ) -> List[LeadScore]:
        results: List[LeadScore] = []
        scanned_domains: List[str] = []
        total = len(companies)

        if resume:
            prev_domains, prev_results = self._load_incremental()
            if prev_domains:
                scanned_domains = prev_domains
                logger.info("Resuming scan: %s companies already scanned", len(prev_domains))
                remaining_companies = [c for c in companies if c.domain not in scanned_domains]
                if len(remaining_companies) < len(companies):
                    logger.info(
                        "Skipping %s already scanned companies",
                        len(companies) - len(remaining_companies),
                    )
                    companies = remaining_companies
                    self._prev_results_data = prev_results
                else:
                    self._prev_results_data = []
            else:
                self._prev_results_data = []
        else:
            self._prev_results_data = []

        logger.debug("=" * 60)
        logger.debug("NEW SCAN SESSION STARTED")
        logger.debug("Companies to scan: %s", [c.domain for c in companies])
        logger.debug(
            "Settings: timeout=%ss, delay=%ss, workers=%s",
            self.timeout,
            delay,
            max_workers,
        )
        logger.debug("=" * 60)
        logger.info("Starting scan of %s companies...", len(companies))
        logger.info("Estimated time: ~%s seconds", len(companies) * (delay + 5))
        print()

        if max_workers == 1:
            for i, company in enumerate(companies, 1):
                try:
                    result = self.scan_company(company)
                    results.append(result)
                    scanned_domains.append(company.domain)
                    self._save_incremental(results, scanned_domains)
                except KeyboardInterrupt:
                    logger.warning(
                        "Scan interrupted by user while scanning %s (%s)",
                        company.name,
                        company.domain,
                    )
                    logger.info("Progress saved to %s", self.incremental_save_path)
                    logger.info("Run again with same input to resume")
                    break
                except Exception as exc:
                    logger.error("Failed to scan %s: %s", company.name, exc)
                    scanned_domains.append(company.domain)
                    self._save_incremental(results, scanned_domains)

                total_done = len(scanned_domains)
                print(f"  Progress: {total_done}/{total} ({total_done/total*100:.0f}%)")

                if i < len(companies) and delay > 0:
                    time.sleep(delay)
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(self.scan_company, company): company for company in companies}
                for future in as_completed(futures):
                    company = futures[future]
                    try:
                        result = future.result()
                        results.append(result)
                        scanned_domains.append(company.domain)
                        self._save_incremental(results, scanned_domains)
                    except Exception as exc:
                        logger.error("Failed to scan %s: %s", company.name, exc)
                        scanned_domains.append(company.domain)
                        self._save_incremental(results, scanned_domains)

        print()
        logger.info("Completed scanning %s new companies", len(results))

        if len(companies) == 0 or len(results) == len(companies):
            self._clear_incremental()
            logger.info("Scan complete - incremental save cleared")

        return results

    def generate_report(
        self,
        leads: List[LeadScore],
        output_path: str,
        json_output: Optional[str] = None,
        html_output: Optional[str] = None,
        *,
        include_sales_angles: bool = True,
        include_json_export: bool = True,
        html_filter_mode: str = "advanced",
        html_allow_table_sort: bool = True,
    ) -> str:
        return self.assessment_service.generate_lead_report_set(
            leads,
            output_path,
            json_output=json_output,
            html_output=html_output,
            include_sales_angles=include_sales_angles,
            include_json_export=include_json_export,
            html_filter_mode=html_filter_mode,
            html_allow_table_sort=html_allow_table_sort,
        )


def load_csv(filepath: str) -> List[CompanyInput]:
    companies = []
    with open(filepath, "r", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            name = row.get("name") or row.get("Name") or row.get("company") or row.get("Company", "")
            domain = row.get("domain") or row.get("Domain") or row.get("website", "")
            sector = (
                row.get("sector")
                or row.get("Sector")
                or row.get("industry")
                or row.get("Industry", "Unknown")
            )
            employees_str = row.get("employees") or row.get("Employees") or row.get("size", "100")
            try:
                employees_clean = "".join(c for c in employees_str if c.isdigit())
                employees = int(employees_clean) if employees_clean else 100
            except ValueError:
                employees = 100

            if name and domain:
                domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
                companies.append(
                    CompanyInput(
                        name=name.strip(),
                        domain=domain.strip(),
                        sector=sector.strip(),
                        employees=employees,
                    )
                )
    return companies


def load_json(filepath: str) -> List[CompanyInput]:
    with open(filepath, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    companies = []
    if isinstance(data, dict):
        data = data.get("companies", [])

    for item in data:
        companies.append(
            CompanyInput(
                name=item.get("name", ""),
                domain=item.get("domain", ""),
                sector=item.get("sector", "Unknown"),
                employees=item.get("employees", 100),
            )
        )
    return [c for c in companies if c.name and c.domain]


def main():
    parser = argparse.ArgumentParser(
        description="Lead Scout - NIS2 OSINT Scanner for Nomios",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scout.py --input data/sample_companies.csv --output output/report.md
  python scout.py --domain forfarmers.nl --name "ForFarmers" --sector "Food" --employees 2500
  python scout.py --input data/sample_companies.csv --output output/report.md --verbose
  python scout.py --input data/sample_companies.csv --output output/report.md --json output/data.json
        """,
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--input", "-i", help="Path to CSV or JSON file with companies to scan")
    input_group.add_argument("--domain", "-d", help="Single domain to scan")

    parser.add_argument("--name", "-n", help="Company name (for single domain scan)")
    parser.add_argument("--sector", "-s", default="Unknown", help="Company sector")
    parser.add_argument("--employees", "-e", type=int, default=100, help="Employee count estimate")
    parser.add_argument("--output", "-o", default="output/report.md", help="Path for markdown report")
    parser.add_argument("--json", "-j", help="Path for JSON data output")
    parser.add_argument("--timeout", "-t", type=float, default=8.0, help="Timeout per scan operation in seconds")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between companies in seconds")
    parser.add_argument("--workers", "-w", type=int, default=1, help="Max parallel workers")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    if args.input:
        filepath = Path(args.input)
        if not filepath.exists():
            print(f"Error: Input file not found: {filepath}")
            sys.exit(1)
        companies = load_json(str(filepath)) if filepath.suffix.lower() == ".json" else load_csv(str(filepath))
    else:
        companies = [
            CompanyInput(
                name=args.name or args.domain,
                domain=args.domain,
                sector=args.sector,
                employees=args.employees,
            )
        ]

    if not companies:
        print("No valid companies found to scan.")
        sys.exit(1)

    scout = LeadScout(timeout=args.timeout, verbose=args.verbose)
    leads = scout.scan_companies(companies, max_workers=args.workers, delay=args.delay)

    if not leads:
        print("No scan results generated.")
        sys.exit(1)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    scout.generate_report(leads, args.output, json_output=args.json)
    print(f"\nReport written to {args.output}")


if __name__ == "__main__":
    main()
