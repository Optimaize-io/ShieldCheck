#!/usr/bin/env python3
"""
ShieldCheck self-check website.
"""

import argparse
import json
import logging
import os
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from flask import (
    Blueprint,
    Flask,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from assessment_service import AssessmentService
from mailer import send_self_check_report
from models import CompanyInput
from persistence import (
    create_self_check_run,
    get_self_check_run,
    init_db,
    update_self_check_run,
)
from reports.selfcheck_html_report import SelfCheckHTMLReportGenerator


def _clean_prefix(value: str) -> str:
    value = (value or "").strip()
    if not value or value == "/":
        return ""
    return "/" + value.strip("/")


SELFCHECK_URL_PREFIX = _clean_prefix(os.environ.get("SELFCHECK_URL_PREFIX", "/self-check"))
SELFCHECK_PUBLIC_BASE_URL = os.environ.get("SELFCHECK_PUBLIC_BASE_URL", "").rstrip("/")
SELFCHECK_STATIC_URL_PATH = (
    f"{SELFCHECK_URL_PREFIX}/static" if SELFCHECK_URL_PREFIX else "/static"
)

app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "web_selfcheck" / "templates"),
    static_folder=str(Path(__file__).parent / "web_selfcheck" / "static"),
    static_url_path=SELFCHECK_STATIC_URL_PATH,
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

selfcheck = Blueprint("selfcheck", __name__)

logger = logging.getLogger(__name__)
init_db()


@dataclass
class SelfCheckState:
    lock: threading.Lock = field(default_factory=threading.Lock)
    running: bool = False
    completed: bool = False
    progress: int = 0
    total: int = 1
    current_step: str = "Waiting to start"
    error: Optional[str] = None
    result: Optional[dict] = None
    log_lines: list[str] = field(default_factory=list)

    def add_log(self, message: str) -> None:
        with self.lock:
            self.log_lines.append(message)

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "running": self.running,
                "completed": self.completed,
                "progress": self.progress,
                "total": self.total,
                "current_step": self.current_step,
                "error": self.error,
                "result": self.result,
                "log": list(self.log_lines[-80:]),
            }


_state_lock = threading.Lock()
_states: Dict[str, SelfCheckState] = {}


def get_state(token: str) -> SelfCheckState:
    with _state_lock:
        if token not in _states:
            _states[token] = SelfCheckState()
        return _states[token]


def normalize_domain(raw: str) -> str:
    domain = (raw or "").strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/", 1)[0].strip(".")
    return domain


def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    return re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,63}", domain) is not None


def derive_company_name(domain: str) -> str:
    root = domain.split(".")[0].replace("-", " ").strip()
    return root.title() if root else domain


def posture_label_from_tier(tier: Optional[str]) -> str:
    text = (tier or "").upper()
    if "HOT" in text:
        return "Needs attention"
    if "WARM" in text:
        return "Some improvements advised"
    if "COOL" in text:
        return "Good baseline visible"
    return "Assessment ready"


def build_public_url(endpoint: str, **values) -> str:
    path = url_for(endpoint, **values)
    if SELFCHECK_PUBLIC_BASE_URL:
        return f"{SELFCHECK_PUBLIC_BASE_URL}{path}"
    return request.url_root.rstrip("/") + path


def _write_json(output_path: Path, payload: dict) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


def _scan_worker(token: str, company: CompanyInput, timeout: float) -> None:
    state = get_state(token)
    output_dir = Path(__file__).parent / "output" / "selfcheck"
    output_dir.mkdir(parents=True, exist_ok=True)

    with state.lock:
        state.running = True
        state.completed = False
        state.progress = 0
        state.current_step = "Preparing scan"
        state.error = None

    update_self_check_run(token, status="running")
    state.add_log(f"Started self-check for {company.domain}")

    try:
        state.current_step = "Running public checks"
        service = AssessmentService(timeout=timeout, verbose=False)
        lead = service.scan_company(company)

        state.progress = 1
        state.current_step = "Preparing report"

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"selfcheck_{timestamp}_{token[:8]}"
        json_path = output_dir / f"{base_name}.json"
        html_path = output_dir / f"{base_name}.html"
        pdf_path = output_dir / f"{base_name}.pdf"

        _write_json(
            json_path,
            {
                "generated_at": datetime.now().isoformat(),
                "lead": lead.to_dict(),
            },
        )

        pdf_url = url_for("selfcheck.self_check_pdf", token=token)
        SelfCheckHTMLReportGenerator().generate(lead, str(html_path), pdf_url=pdf_url)
        service.generate_company_pdf(lead, str(pdf_path))

        result_dict = lead.to_dict()
        with state.lock:
            state.result = result_dict
            state.running = False
            state.completed = True
            state.current_step = "Scan complete"

        update_self_check_run(
            token,
            status="completed",
            report_html_path=str(html_path),
            report_pdf_path=str(pdf_path),
            report_json_path=str(json_path),
            findings_count=int(lead.findings_count),
            total_score=float(lead.total_score),
            max_score=float(lead.max_score),
            tier=lead.tier.value,
            set_completed_at=True,
        )
        state.add_log("Report ready")
    except Exception as exc:
        with state.lock:
            state.running = False
            state.completed = False
            state.error = str(exc)
            state.current_step = "Scan failed"
        update_self_check_run(token, status="failed")
        state.add_log(f"Scan failed: {exc}")


if SELFCHECK_URL_PREFIX:
    @app.route("/")
    def root():
        return redirect(url_for("selfcheck.self_check_start"))


@selfcheck.route("/")
def self_check_start():
    return render_template("start.html", error=None, domain="")


@selfcheck.route("/start", methods=["POST"])
def self_check_start_post():
    domain = normalize_domain(request.form.get("domain", ""))
    if not is_valid_domain(domain):
        return render_template(
            "start.html",
            error="Enter a valid domain, for example example.nl.",
            domain=domain,
        )

    token = uuid.uuid4().hex
    company = CompanyInput(
        name=derive_company_name(domain),
        domain=domain,
        sector="Unknown",
        employees=100,
    )
    create_self_check_run(
        token=token,
        domain=company.domain,
        company_name=company.name,
        sector=company.sector,
        employees=company.employees,
        status="queued",
    )

    thread = threading.Thread(target=_scan_worker, args=(token, company, 8.0), daemon=True)
    thread.start()
    return redirect(url_for("selfcheck.self_check_scan", token=token))


@selfcheck.route("/scan/<token>")
def self_check_scan(token: str):
    row = get_self_check_run(token)
    if not row:
        return redirect(url_for("selfcheck.self_check_start"))
    return render_template("scan.html", token=token, domain=row["domain"])


@selfcheck.route("/api/status/<token>")
def self_check_status(token: str):
    row = get_self_check_run(token)
    if not row:
        return {"error": "Not found"}, 404

    snap = get_state(token).snapshot()
    response = {
        **snap,
        "status": row["status"],
        "next_url": None,
    }
    if row["status"] == "completed" and not row.get("submitted_at"):
        response["next_url"] = url_for("selfcheck.self_check_details", token=token)
    elif row.get("submitted_at") and row.get("report_html_path"):
        response["next_url"] = url_for("selfcheck.self_check_report", token=token)
    return response


@selfcheck.route("/details/<token>", methods=["GET", "POST"])
def self_check_details(token: str):
    row = get_self_check_run(token)
    if not row:
        return redirect(url_for("selfcheck.self_check_start"))
    if row["status"] != "completed":
        return redirect(url_for("selfcheck.self_check_scan", token=token))
    if row.get("submitted_at") and row.get("report_html_path"):
        return redirect(url_for("selfcheck.self_check_report", token=token))

    error = None
    if request.method == "POST":
        contact_name = (request.form.get("contact_name") or "").strip()
        contact_email = (request.form.get("contact_email") or "").strip()
        if not contact_email or "@" not in contact_email:
            error = "Enter a valid email address."
        else:
            report_url = build_public_url("selfcheck.self_check_report", token=token)
            email_status = send_self_check_report(
                recipient_email=contact_email,
                recipient_name=contact_name,
                domain=row["domain"],
                pdf_path=row["report_pdf_path"],
                report_url=report_url,
            )
            update_self_check_run(
                token,
                status="submitted",
                contact_name=contact_name,
                contact_email=contact_email,
                email_delivery_status=email_status,
                set_submitted_at=True,
                set_emailed_at=email_status == "sent",
            )
            return redirect(url_for("selfcheck.self_check_report", token=token))

    return render_template(
        "details.html",
        row=row,
        error=error,
        posture_label=posture_label_from_tier(row.get("tier")),
    )


@selfcheck.route("/report/<token>")
def self_check_report(token: str):
    row = get_self_check_run(token)
    if not row:
        return redirect(url_for("selfcheck.self_check_start"))
    if row["status"] not in {"completed", "submitted"}:
        return redirect(url_for("selfcheck.self_check_scan", token=token))
    if not row.get("submitted_at"):
        return redirect(url_for("selfcheck.self_check_details", token=token))
    report_path = row.get("report_html_path")
    if not report_path:
        return redirect(url_for("selfcheck.self_check_details", token=token))
    report_file = Path(report_path)
    return send_from_directory(str(report_file.parent), report_file.name)


@selfcheck.route("/pdf/<token>")
def self_check_pdf(token: str):
    row = get_self_check_run(token)
    if not row or not row.get("report_pdf_path"):
        return {"error": "Not found"}, 404
    pdf_path = Path(row["report_pdf_path"])
    return send_from_directory(str(pdf_path.parent), pdf_path.name, as_attachment=True)


app.register_blueprint(selfcheck, url_prefix=SELFCHECK_URL_PREFIX)


def main():
    parser = argparse.ArgumentParser(description="ShieldCheck self-check website")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    print(f"\n  ShieldCheck self-check - http://{args.host}:{args.port}{SELFCHECK_URL_PREFIX or '/'}\n")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
