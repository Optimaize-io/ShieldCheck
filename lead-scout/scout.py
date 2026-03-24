#!/usr/bin/env python3
"""
Lead Scout - NIS2 OSINT Scanner for Nomios
Main CLI entry point.

Scans Dutch companies for public security weaknesses and NIS2 compliance gaps.
Generates prioritized lead reports for sales outreach.

Usage:
    python scout.py --input data/sample_companies.csv --output output/report.md
    python scout.py --domain forfarmers.nl --name "ForFarmers" --sector "Food"
"""

import argparse
import csv
import json
import logging
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import List, Optional, Callable, TypeVar, Any

T = TypeVar('T')

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from scanners.dns_scanner import DNSScanner
from scanners.shodan_scanner import ShodanScanner
from scanners.ssl_scanner import SSLScanner
from scanners.website_scanner import WebsiteScanner
from scanners.jobs_scanner import JobsScanner
from scanners.governance_scanner import GovernanceScanner
from scanners.admin_scanner import AdminScanner
from scanners.headers_scanner import HeadersScanner
from scanners.cookie_scanner import CookieScanner
from scanners.subdomain_scanner import SubdomainScanner
from scanners.techstack_scanner import TechStackScanner
from scoring.scorer import LeadScorer, LeadScore
from reports.markdown_report import MarkdownReportGenerator
from reports.html_report import HTMLReportGenerator
from reports.pdf_report import PDFReportGenerator


# Configure logging - both console and file
LOG_FILE = Path(__file__).parent / "output" / "scout.log"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

# Create formatters
log_format = '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
console_format = '%(asctime)s - %(levelname)s - %(message)s'

# Root logger setup
root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)

# Console handler (INFO level)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter(console_format, datefmt='%H:%M:%S'))
root_logger.addHandler(console_handler)

# File handler (DEBUG level - captures everything)
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter(log_format, datefmt='%Y-%m-%d %H:%M:%S'))
root_logger.addHandler(file_handler)

logger = logging.getLogger(__name__)


class ScanTimeoutError(Exception):
    """Raised when a scan operation times out."""
    pass


def run_with_timeout(func: Callable[..., T], timeout: float, *args, **kwargs) -> Optional[T]:
    """
    Run a function with a timeout. Returns None if timeout occurs.
    
    Args:
        func: Function to execute
        timeout: Timeout in seconds
        *args, **kwargs: Arguments to pass to function
        
    Returns:
        Function result or None if timeout
    """
    result_container = {"result": None, "exception": None}
    
    def target():
        try:
            result_container["result"] = func(*args, **kwargs)
        except Exception as e:
            result_container["exception"] = e
    
    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout=timeout)
    
    if thread.is_alive():
        logger.debug(f"Timeout after {timeout}s for {func.__name__ if hasattr(func, '__name__') else 'function'}")
        return None
    
    if result_container["exception"]:
        raise result_container["exception"]
    
    return result_container["result"]


@dataclass
class CompanyInput:
    """Input data for a company to scan."""
    name: str
    domain: str
    sector: str
    employees: int


class LeadScout:
    """
    Main Lead Scout orchestrator.
    Coordinates all scanners and generates reports.
    """
    
    def __init__(self, timeout: float = 8.0, verbose: bool = False, incremental_save_path: Optional[str] = None):
        """
        Initialize Lead Scout.
        
        Args:
            timeout: Timeout for each scan operation
            verbose: Enable verbose logging
            incremental_save_path: Optional path to save incremental results (prevents data loss on interrupt)
        """
        self.timeout = timeout
        self.verbose = verbose
        self.incremental_save_path = incremental_save_path or "output/.scan_progress.json"
        
        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Initialize scanners
        self.dns_scanner = DNSScanner(timeout=timeout)
        self.shodan_scanner = ShodanScanner(timeout=timeout)
        self.ssl_scanner = SSLScanner(timeout=timeout)
        self.website_scanner = WebsiteScanner(timeout=timeout)
        self.jobs_scanner = JobsScanner(timeout=timeout)
        self.governance_scanner = GovernanceScanner(timeout=timeout)
        self.admin_scanner = AdminScanner(timeout=timeout)
        self.headers_scanner = HeadersScanner(timeout=timeout)
        self.cookie_scanner = CookieScanner(timeout=timeout)
        self.subdomain_scanner = SubdomainScanner(timeout=20.0)  # crt.sh needs longer timeout
        self.techstack_scanner = TechStackScanner(timeout=timeout)
        
        # Initialize scorer and report generators
        self.scorer = LeadScorer()
        self.report_generator = MarkdownReportGenerator()
        self.html_report_generator = HTMLReportGenerator()
        self.pdf_report_generator = PDFReportGenerator()
    
    def _save_incremental(self, results: List[LeadScore], scanned_domains: List[str]) -> None:
        """
        Save incremental scan progress to prevent data loss.
        
        Args:
            results: Current list of LeadScore results
            scanned_domains: List of domains already scanned
        """
        try:
            progress_data = {
                "scanned_domains": scanned_domains,
                "results": [lead.to_dict() for lead in results],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")
            }
            Path(self.incremental_save_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.incremental_save_path, 'w', encoding='utf-8') as f:
                json.dump(progress_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.warning(f"Failed to save incremental progress: {e}")
    
    def _load_incremental(self) -> tuple:
        """
        Load incremental scan progress if available.
        
        Returns:
            Tuple of (scanned_domains, results_data) or ([], []) if not found
        """
        try:
            if Path(self.incremental_save_path).exists():
                with open(self.incremental_save_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                return data.get("scanned_domains", []), data.get("results", [])
        except Exception as e:
            logger.warning(f"Could not load incremental progress: {e}")
        return [], []
    
    def _clear_incremental(self) -> None:
        """Remove incremental save file after successful completion."""
        try:
            if Path(self.incremental_save_path).exists():
                Path(self.incremental_save_path).unlink()
        except Exception as e:
            logger.warning(f"Could not remove incremental file: {e}")
    
    def _run_scan(self, scan_name: str, scanner_func: Callable, *args, scan_timeout: Optional[float] = None, **kwargs) -> Optional[Any]:
        """
        Run a scan with timeout protection and error handling.
        
        Args:
            scan_name: Name of the scan for logging
            scanner_func: Scanner function to call
            *args: Positional arguments for scanner
            scan_timeout: Override timeout for this specific scan
            **kwargs: Keyword arguments for scanner
            
        Returns:
            Scan result or None if failed/timed out
        """
        timeout = scan_timeout or self.timeout + 5  # Add buffer to internal timeout
        logger.debug(f"  {scan_name}...")
        
        try:
            result = run_with_timeout(scanner_func, timeout, *args, **kwargs)
            if result is None:
                logger.warning(f"  {scan_name} timed out after {timeout}s")
            return result
        except Exception as e:
            logger.warning(f"  {scan_name} failed: {e}")
            logger.debug(f"  {scan_name} exception details: {type(e).__name__}: {e}")
            return None

    def scan_company(self, company: CompanyInput) -> LeadScore:
        """
        Perform full scan of a single company with timeout protection.
        
        Args:
            company: Company input data
            
        Returns:
            Complete LeadScore
        """
        logger.info(f"Scanning {company.name} ({company.domain})...")
        
        # Run all scans with timeout protection
        dns_result = self._run_scan("DNS scan", self.dns_scanner.scan, company.domain)
        shodan_result = self._run_scan("Shodan scan", self.shodan_scanner.scan, company.domain)
        ssl_result = self._run_scan("SSL scan", self.ssl_scanner.scan, company.domain)
        
        # Fetch homepage once and reuse for multiple scanners
        homepage_response = None
        homepage_html = None
        
        def fetch_homepage():
            import requests
            session = requests.Session()
            session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml",
            })
            response = session.get(f"https://{company.domain}", timeout=self.timeout, allow_redirects=True)
            return response, response.text
        
        homepage_data = self._run_scan("Homepage fetch", fetch_homepage)
        if homepage_data:
            homepage_response, homepage_html = homepage_data
        
        website_result = self._run_scan("Website scan", self.website_scanner.scan, company.domain)
        headers_result = self._run_scan("Headers scan", self.headers_scanner.scan, company.domain, response=homepage_response)
        cookie_result = self._run_scan("Cookie scan", self.cookie_scanner.scan, company.domain, response=homepage_response, html_content=homepage_html)
        techstack_result = self._run_scan("Tech stack scan", self.techstack_scanner.scan, company.domain, response=homepage_response, html_content=homepage_html)
        
        # crt.sh needs longer timeout
        subdomain_result = self._run_scan("Subdomain scan (crt.sh)", self.subdomain_scanner.scan, company.domain, scan_timeout=30.0)
        
        jobs_result = self._run_scan("Jobs scan", self.jobs_scanner.scan, company.domain)
        governance_result = self._run_scan("Governance scan", self.governance_scanner.scan, company.domain)
        admin_result = self._run_scan("Admin scan", self.admin_scanner.scan, company.domain)
        
        # Score the company
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
            techstack_result=techstack_result
        )
        
        logger.info(f"  ✓ {company.name}: Score {lead_score.total_score:.1f}/10 ({lead_score.tier.value})")
        
        return lead_score
    
    def scan_companies(
        self, 
        companies: List[CompanyInput], 
        max_workers: int = 1,
        delay: float = 1.0,
        resume: bool = True
    ) -> List[LeadScore]:
        """
        Scan multiple companies with incremental save.
        
        Args:
            companies: List of companies to scan
            max_workers: Max parallel workers (default 1 for rate limiting)
            delay: Delay between companies in seconds
            resume: If True, resume from previous interrupted scan
            
        Returns:
            List of LeadScores
        """
        results: List[LeadScore] = []
        scanned_domains: List[str] = []
        total = len(companies)
        
        # Try to resume from previous scan
        if resume:
            prev_domains, prev_results = self._load_incremental()
            if prev_domains:
                scanned_domains = prev_domains
                # Convert dict results back to pseudo-LeadScores for temp storage
                # We store them as dicts and will merge at the end
                logger.info(f"Resuming scan: {len(prev_domains)} companies already scanned")
                for prev_result in prev_results:
                    # We'll just keep the dicts and append new LeadScores
                    pass
                # Filter out already scanned companies
                remaining_companies = [c for c in companies if c.domain not in scanned_domains]
                if len(remaining_companies) < len(companies):
                    logger.info(f"Skipping {len(companies) - len(remaining_companies)} already scanned companies")
                    companies = remaining_companies
                    # Store previous results to merge later
                    self._prev_results_data = prev_results
                else:
                    self._prev_results_data = []
            else:
                self._prev_results_data = []
        else:
            self._prev_results_data = []
        
        logger.debug("=" * 60)
        logger.debug(f"NEW SCAN SESSION STARTED")
        logger.debug(f"Companies to scan: {[c.domain for c in companies]}")
        logger.debug(f"Settings: timeout={self.timeout}s, delay={delay}s, workers={max_workers}")
        logger.debug("=" * 60)
        logger.info(f"Starting scan of {len(companies)} companies...")
        logger.info(f"Estimated time: ~{len(companies) * (delay + 5)} seconds")
        print()
        
        if max_workers == 1:
            # Sequential scanning with delays
            for i, company in enumerate(companies, 1):
                try:
                    result = self.scan_company(company)
                    results.append(result)
                    scanned_domains.append(company.domain)
                    
                    # Save incremental progress after each company
                    self._save_incremental(results, scanned_domains)
                    
                except KeyboardInterrupt:
                    logger.warning(f"Scan interrupted by user while scanning {company.name} ({company.domain})")
                    logger.debug(f"Interrupt details: completed {len(results)}/{len(companies)} scans")
                    logger.info(f"Progress saved to {self.incremental_save_path}")
                    logger.info("Run again with same input to resume")
                    break
                except Exception as e:
                    import traceback
                    logger.error(f"Failed to scan {company.name}: {e}")
                    logger.debug(f"Full exception for {company.name}:\n{traceback.format_exc()}")
                    scanned_domains.append(company.domain)  # Mark as scanned to skip on resume
                    self._save_incremental(results, scanned_domains)
                
                # Progress update
                total_done = len(scanned_domains)
                total_all = total
                print(f"  Progress: {total_done}/{total_all} ({total_done/total_all*100:.0f}%)")
                
                # Be polite - wait between companies
                if i < len(companies) and delay > 0:
                    time.sleep(delay)
        else:
            # Parallel scanning (use with caution due to rate limits)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {}
                for company in companies:
                    future = executor.submit(self.scan_company, company)
                    futures[future] = company
                
                for future in as_completed(futures):
                    company = futures[future]
                    try:
                        result = future.result()
                        results.append(result)
                        scanned_domains.append(company.domain)
                        self._save_incremental(results, scanned_domains)
                    except Exception as e:
                        logger.error(f"Failed to scan {company.name}: {e}")
                        scanned_domains.append(company.domain)
                        self._save_incremental(results, scanned_domains)
        
        print()
        logger.info(f"Completed scanning {len(results)} new companies")
        
        # Clear incremental save on successful completion
        if len(companies) == 0 or len(results) == len(companies):
            self._clear_incremental()
            logger.info("Scan complete - incremental save cleared")
        
        return results
    
    def generate_report(
        self, 
        leads: List[LeadScore], 
        output_path: str,
        json_output: Optional[str] = None,
        html_output: Optional[str] = None
    ) -> str:
        """
        Generate report from scan results.
        
        Args:
            leads: List of lead scores
            output_path: Path for markdown report
            json_output: Optional path for JSON data
            html_output: Optional path for HTML dashboard
            
        Returns:
            Markdown report content
        """
        logger.info(f"Generating report to {output_path}...")
        
        # Generate markdown report
        report = self.report_generator.generate(leads, output_path)
        
        # Generate JSON if requested
        if json_output:
            self.report_generator.generate_json(leads, json_output)
            logger.info(f"JSON data written to {json_output}")
        
        # Generate HTML dashboard if requested (or auto-generate alongside markdown)
        if html_output:
            self.html_report_generator.generate(leads, html_output)
            logger.info(f"HTML dashboard written to {html_output}")
        else:
            # Auto-generate HTML alongside markdown
            html_path = output_path.replace('.md', '.html')
            if html_path != output_path:  # Only if it's a .md file
                self.html_report_generator.generate(leads, html_path)
                logger.info(f"HTML dashboard written to {html_path}")
        
        logger.info(f"Report complete: {output_path}")
        
        return report


def load_csv(filepath: str) -> List[CompanyInput]:
    """Load companies from CSV file."""
    companies = []
    
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            # Handle various column name formats
            name = row.get('name') or row.get('Name') or row.get('company') or row.get('Company', '')
            domain = row.get('domain') or row.get('Domain') or row.get('website', '')
            sector = row.get('sector') or row.get('Sector') or row.get('industry') or row.get('Industry', 'Unknown')
            
            # Parse employees - handle various formats
            employees_str = row.get('employees') or row.get('Employees') or row.get('size', '100')
            try:
                # Remove non-numeric characters
                employees_clean = ''.join(c for c in employees_str if c.isdigit())
                employees = int(employees_clean) if employees_clean else 100
            except ValueError:
                employees = 100
            
            if name and domain:
                # Clean domain - remove http:// or https:// if present
                domain = domain.replace('https://', '').replace('http://', '')
                domain = domain.rstrip('/')
                
                companies.append(CompanyInput(
                    name=name.strip(),
                    domain=domain.strip(),
                    sector=sector.strip(),
                    employees=employees
                ))
    
    return companies


def load_json(filepath: str) -> List[CompanyInput]:
    """Load companies from JSON file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    companies = []
    
    # Handle both list and dict with 'companies' key
    if isinstance(data, dict):
        data = data.get('companies', [])
    
    for item in data:
        companies.append(CompanyInput(
            name=item.get('name', ''),
            domain=item.get('domain', ''),
            sector=item.get('sector', 'Unknown'),
            employees=item.get('employees', 100)
        ))
    
    return [c for c in companies if c.name and c.domain]


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Lead Scout - NIS2 OSINT Scanner for Nomios',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan from CSV file
  python scout.py --input data/sample_companies.csv --output output/report.md

  # Scan a single domain
  python scout.py --domain forfarmers.nl --name "ForFarmers" --sector "Food" --employees 2500

  # Scan with verbose output
  python scout.py --input data/sample_companies.csv --output output/report.md --verbose

  # Generate JSON output too
  python scout.py --input data/sample_companies.csv --output output/report.md --json output/data.json
        """
    )
    
    # Input options (mutually exclusive groups)
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument(
        '--input', '-i',
        help='Path to CSV or JSON file with companies to scan'
    )
    input_group.add_argument(
        '--domain', '-d',
        help='Single domain to scan'
    )
    input_group.add_argument(
        '--name', '-n',
        help='Company name (for single domain scan)'
    )
    input_group.add_argument(
        '--sector', '-s',
        default='Unknown',
        help='Company sector (for single domain scan)'
    )
    input_group.add_argument(
        '--employees', '-e',
        type=int,
        default=100,
        help='Employee count estimate (for single domain scan)'
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '--output', '-o',
        default='output/report.md',
        help='Path for markdown report (default: output/report.md)'
    )
    output_group.add_argument(
        '--json', '-j',
        help='Path for JSON data output'
    )
    output_group.add_argument(
        '--pdf',
        action='store_true',
        help='Generate individual PDF reports for each company'
    )
    output_group.add_argument(
        '--pdf-dir',
        default='output/pdfs',
        help='Directory for PDF reports (default: output/pdfs)'
    )
    
    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument(
        '--timeout', '-t',
        type=float,
        default=8.0,
        help='Timeout for each scan operation in seconds (default: 8)'
    )
    scan_group.add_argument(
        '--delay',
        type=float,
        default=1.0,
        help='Delay between companies in seconds (default: 1)'
    )
    scan_group.add_argument(
        '--workers', '-w',
        type=int,
        default=1,
        help='Max parallel workers (default: 1, be careful with rate limits)'
    )
    scan_group.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    scan_group.add_argument(
        '--no-resume',
        action='store_true',
        help='Start fresh scan without resuming from previous interrupted scan'
    )
    
    args = parser.parse_args()
    
    # Validate input
    if not args.input and not args.domain:
        parser.error("Either --input or --domain is required")
    
    if args.domain and not args.name:
        parser.error("--name is required when using --domain")
    
    # Load companies
    companies: List[CompanyInput] = []
    
    if args.input:
        filepath = Path(args.input)
        if not filepath.exists():
            logger.error(f"Input file not found: {args.input}")
            sys.exit(1)
        
        if filepath.suffix.lower() == '.json':
            companies = load_json(str(filepath))
        else:
            companies = load_csv(str(filepath))
        
        if not companies:
            logger.error("No valid companies found in input file")
            sys.exit(1)
        
        logger.info(f"Loaded {len(companies)} companies from {args.input}")
    
    elif args.domain:
        companies = [CompanyInput(
            name=args.name,
            domain=args.domain,
            sector=args.sector,
            employees=args.employees
        )]
    
    # Initialize scanner
    scout = LeadScout(timeout=args.timeout, verbose=args.verbose)
    
    # Run scans
    try:
        results = scout.scan_companies(
            companies,
            max_workers=args.workers,
            delay=args.delay,
            resume=not args.no_resume
        )
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        logger.info(f"Progress saved. Run again to resume.")
        sys.exit(1)
    
    if not results:
        logger.error("No successful scans")
        sys.exit(1)
    
    # Generate report
    json_output = args.json
    if not json_output:
        # Generate default JSON path next to markdown
        md_path = Path(args.output)
        json_output = str(md_path.parent / (md_path.stem + '_data.json'))
    
    report = scout.generate_report(results, args.output, json_output)
    
    # Always generate PDF reports
    pdf_paths = []
    pdf_dir = args.pdf_dir
    logger.info(f"Generating PDF reports to {pdf_dir}...")
    try:
        Path(pdf_dir).mkdir(parents=True, exist_ok=True)
        for lead in results:
            try:
                pdf_path = scout.pdf_report_generator.generate(
                    lead,
                    str(Path(pdf_dir) / f"security_report_{lead.domain.replace('.', '_')}.pdf")
                )
                pdf_paths.append(pdf_path)
                logger.info(f"  ✓ PDF generated: {pdf_path}")
            except Exception as e:
                logger.error(f"  ✗ PDF failed for {lead.company_name}: {e}")
    except ImportError as e:
        logger.error(f"PDF generation requires reportlab. Install with: pip install reportlab")
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
    
    # Print summary
    print("\n" + "="*60)
    print("SCAN COMPLETE")
    print("="*60)
    
    from scoring.scorer import LeadTier
    hot = sum(1 for r in results if r.tier == LeadTier.HOT)
    warm = sum(1 for r in results if r.tier == LeadTier.WARM)
    cool = sum(1 for r in results if r.tier == LeadTier.COOL)
    
    print(f"\n🔴 HOT leads:  {hot}")
    print(f"🟠 WARM leads: {warm}")
    print(f"🟢 COOL leads: {cool}")
    print(f"\n📄 Report: {args.output}")
    print(f"📊 Data:   {json_output}")
    if pdf_paths:
        print(f"📑 PDFs:   {len(pdf_paths)} reports in {pdf_dir}")
    print()


if __name__ == '__main__':
    main()
