import json
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar

from models import CompanyInput
from reports.html_report import HTMLReportGenerator
from reports.markdown_report import MarkdownReportGenerator
from reports.pdf_report import PDFReportGenerator
from scanners.admin_scanner import AdminScanner
from scanners.cookie_scanner import CookieScanner
from scanners.dns_scanner import DNSScanner
from scanners.governance_scanner import GovernanceScanner
from scanners.headers_scanner import HeadersScanner
from scanners.jobs_scanner import JobsScanner
from scanners.shodan_scanner import ShodanScanner
from scanners.ssl_scanner import SSLScanner
from scanners.subdomain_scanner import SubdomainScanner
from scanners.techstack_scanner import TechStackScanner
from scanners.website_scanner import WebsiteScanner
from scoring.scorer import LeadScore, LeadScorer

T = TypeVar("T")

logger = logging.getLogger(__name__)


def run_with_timeout(
    func: Callable[..., T], timeout: float, *args, **kwargs
) -> Optional[T]:
    """Run a function with a timeout. Returns None if timeout occurs."""

    result_container = {"result": None, "exception": None}

    def target():
        try:
            result_container["result"] = func(*args, **kwargs)
        except Exception as exc:  # pragma: no cover - passthrough container
            result_container["exception"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout=timeout)

    if thread.is_alive():
        logger.debug(
            "Timeout after %ss for %s",
            timeout,
            func.__name__ if hasattr(func, "__name__") else "function",
        )
        return None

    if result_container["exception"]:
        raise result_container["exception"]

    return result_container["result"]


class AssessmentService:
    """Shared assessment pipeline used by the CLI and web apps."""

    def __init__(self, timeout: float = 8.0, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose

        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)

        self.dns_scanner = DNSScanner(timeout=timeout)
        self.shodan_scanner = ShodanScanner(timeout=timeout)
        self.ssl_scanner = SSLScanner(timeout=timeout)
        self.website_scanner = WebsiteScanner(timeout=timeout)
        self.jobs_scanner = JobsScanner(timeout=timeout)
        self.governance_scanner = GovernanceScanner(timeout=timeout)
        self.admin_scanner = AdminScanner(timeout=timeout)
        self.headers_scanner = HeadersScanner(timeout=timeout)
        self.cookie_scanner = CookieScanner(timeout=timeout)
        self.subdomain_scanner = SubdomainScanner(timeout=20.0)
        self.techstack_scanner = TechStackScanner(timeout=timeout)

        self.scorer = LeadScorer()
        self.markdown_report_generator = MarkdownReportGenerator()
        self.html_report_generator = HTMLReportGenerator()
        self.pdf_report_generator = PDFReportGenerator()

    def _run_scan(
        self,
        scan_name: str,
        scanner_func: Callable,
        *args,
        scan_timeout: Optional[float] = None,
        **kwargs,
    ) -> Optional[Any]:
        timeout = scan_timeout or self.timeout + 5
        logger.debug("  %s...", scan_name)

        try:
            result = run_with_timeout(scanner_func, timeout, *args, **kwargs)
            if result is None:
                logger.warning("  %s timed out after %ss", scan_name, timeout)
            return result
        except Exception as exc:
            logger.warning("  %s failed: %s", scan_name, exc)
            logger.debug("  %s exception details: %s: %s", scan_name, type(exc).__name__, exc)
            return None

    def scan_company(self, company: CompanyInput) -> LeadScore:
        logger.info("Scanning %s (%s)...", company.name, company.domain)

        dns_result = self._run_scan("DNS scan", self.dns_scanner.scan, company.domain)
        shodan_result = self._run_scan(
            "Shodan scan", self.shodan_scanner.scan, company.domain
        )
        ssl_result = self._run_scan("SSL scan", self.ssl_scanner.scan, company.domain)

        homepage_response = None
        homepage_html = None

        def fetch_homepage():
            import requests

            session = requests.Session()
            session.headers.update(
                {
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36"
                    ),
                    "Accept": "text/html,application/xhtml+xml",
                }
            )
            response = session.get(
                f"https://{company.domain}",
                timeout=self.timeout,
                allow_redirects=True,
            )
            return response, response.text

        homepage_data = self._run_scan("Homepage fetch", fetch_homepage)
        if homepage_data:
            homepage_response, homepage_html = homepage_data

        website_result = self._run_scan(
            "Website scan", self.website_scanner.scan, company.domain
        )
        headers_result = self._run_scan(
            "Headers scan",
            self.headers_scanner.scan,
            company.domain,
            response=homepage_response,
        )
        cookie_result = self._run_scan(
            "Cookie scan",
            self.cookie_scanner.scan,
            company.domain,
            response=homepage_response,
            html_content=homepage_html,
        )
        techstack_result = self._run_scan(
            "Tech stack scan",
            self.techstack_scanner.scan,
            company.domain,
            response=homepage_response,
            html_content=homepage_html,
        )
        subdomain_result = self._run_scan(
            "Subdomain scan (crt.sh)",
            self.subdomain_scanner.scan,
            company.domain,
            scan_timeout=30.0,
        )
        jobs_result = self._run_scan("Jobs scan", self.jobs_scanner.scan, company.domain)
        governance_result = self._run_scan(
            "Governance scan", self.governance_scanner.scan, company.domain
        )
        admin_result = self._run_scan(
            "Admin scan", self.admin_scanner.scan, company.domain
        )

        lead_score = self.scorer.score(
            company_name=company.name,
            domain=company.domain,
            sector=company.sector,
            employees=company.employees,
            dns_result=dns_result,
            shodan_result=shodan_result,
            ssl_result=ssl_result,
            website_result=website_result,
            jobs_result=jobs_result,
            governance_result=governance_result,
            admin_result=admin_result,
            headers_result=headers_result,
            cookie_result=cookie_result,
            subdomain_result=subdomain_result,
            techstack_result=techstack_result,
        )

        logger.info(
            "  %s: Score %.1f/%s (%s)",
            company.name,
            lead_score.total_score,
            int(lead_score.max_score),
            lead_score.tier.value,
        )
        return lead_score

    def generate_lead_report_set(
        self,
        leads: list[LeadScore],
        output_path: str,
        json_output: Optional[str] = None,
        html_output: Optional[str] = None,
        *,
        include_sales_angles: bool = True,
        include_json_export: bool = True,
        html_filter_mode: str = "advanced",
        html_allow_table_sort: bool = True,
    ) -> str:
        logger.info("Generating report to %s...", output_path)
        report = self.markdown_report_generator.generate(
            leads,
            output_path,
            include_sales_angles=include_sales_angles,
        )

        if json_output:
            self.markdown_report_generator.generate_json(leads, json_output)
            logger.info("JSON data written to %s", json_output)

        if html_output:
            self.html_report_generator.generate(
                leads,
                html_output,
                include_sales_angles=include_sales_angles,
                include_json_export=include_json_export,
                filter_mode=html_filter_mode,
                allow_table_sort=html_allow_table_sort,
            )
            logger.info("HTML dashboard written to %s", html_output)
        else:
            html_path = output_path.replace(".md", ".html")
            if html_path != output_path:
                self.html_report_generator.generate(
                    leads,
                    html_path,
                    include_sales_angles=include_sales_angles,
                    include_json_export=include_json_export,
                    filter_mode=html_filter_mode,
                    allow_table_sort=html_allow_table_sort,
                )
                logger.info("HTML dashboard written to %s", html_path)

        logger.info("Report complete: %s", output_path)
        return report

    def generate_json_file(self, data: dict[str, Any], output_path: str) -> str:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
        return output_path

    def generate_company_pdf(self, lead: LeadScore, output_path: str) -> str:
        return self.pdf_report_generator.generate(lead, output_path)
