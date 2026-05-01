import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from scoring.scorer import LeadScore


class SelfCheckHTMLReportGenerator:
    """Generate a neutral self-check HTML report for a single business."""

    def __init__(self):
        self.generated_at = datetime.now()

    def generate(
        self,
        lead: LeadScore,
        output_path: Optional[str] = None,
        pdf_url: Optional[str] = None,
    ) -> str:
        html = self._build_html(lead, pdf_url=pdf_url)
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as handle:
                handle.write(html)
        return html

    def _build_html(self, lead: LeadScore, pdf_url: Optional[str]) -> str:
        data = lead.to_dict()
        scores = data["scores"]
        generated_at = self.generated_at.strftime("%Y-%m-%d %H:%M")
        posture_label = self._posture_label(lead)
        score_pct = (
            round((lead.total_score / lead.max_score) * 100)
            if lead.max_score
            else 0
        )
        pdf_link = (
            f'<a class="action secondary" href="{pdf_url}">Download PDF</a>'
            if pdf_url
            else ""
        )
        dims_json = json.dumps(scores, ensure_ascii=False)
        findings_html = "".join(
            f"<li>{self._escape(item)}</li>" for item in (lead.key_gaps or ["No major issues were highlighted."])
        )
        positives_html = "".join(
            f"<li>{self._escape(item)}</li>" for item in (lead.positive_findings or ["No positive controls were captured in the scan output."])
        )
        detail_rows = []
        for key, value in scores.items():
            label = key.replace("_", " ").title()
            score = "N/A" if value["score"] is None else f'{value["score"]}/{value["max_score"]}'
            detail_rows.append(
                f"""
                <tr>
                    <td>{self._escape(label)}</td>
                    <td>{score}</td>
                    <td>{self._escape(value.get("description") or "")}</td>
                </tr>
                """
            )
        detail_table = "".join(detail_rows)
        summary = self._owner_summary(lead)
        nis2_summary = self._nis2_summary(lead)
        profile_rows = [
            f"<dt>Domain</dt><dd>{self._escape(lead.domain)}</dd>",
            f"<dt>Generated</dt><dd>{generated_at}</dd>",
            f"<dt>Security posture</dt><dd>{self._escape(posture_label)}</dd>",
            f"<dt>NIS2 applicability</dt><dd>{self._escape(nis2_summary)}</dd>",
        ]
        if lead.sector and lead.sector != "Unknown":
            profile_rows.append(f"<dt>Sector</dt><dd>{self._escape(lead.sector)}</dd>")
        if lead.employees and lead.employees != 100:
            profile_rows.append(f"<dt>Team size used</dt><dd>{lead.employees:,}</dd>")
        profile_html = "".join(profile_rows)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ShieldCheck Report - {self._escape(lead.domain)}</title>
  <style>
    :root {{
      --bg: #f5f7fc;
      --surface: rgba(255, 255, 255, 0.9);
      --surface-strong: #ffffff;
      --panel: #f4f7fd;
      --panel-strong: #ebf1ff;
      --text: #111827;
      --muted: #5f6f8a;
      --border: rgba(117, 133, 165, 0.2);
      --accent: #2563eb;
      --accent-soft: rgba(37, 99, 235, 0.08);
      --warn: #b26b00;
      --warn-soft: #fff2dd;
      --risk: #b42318;
      --risk-soft: #ffe4e2;
      --ok: #157347;
      --ok-soft: #e5f7ee;
      --shadow: 0 18px 40px rgba(15, 23, 42, 0.08);
      --radius-lg: 24px;
      --radius-md: 18px;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, Arial, sans-serif;
      background:
        radial-gradient(circle at top left, rgba(37, 99, 235, 0.1), transparent 28%),
        radial-gradient(circle at top right, rgba(15, 143, 99, 0.08), transparent 22%),
        linear-gradient(180deg, #f9fbff 0%, #f5f7fc 100%);
      color: var(--text);
      line-height: 1.5;
    }}
    .page {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 28px;
    }}
    .hero, .section {{
      background: var(--surface);
      border: 1px solid var(--border);
      box-shadow: var(--shadow);
      backdrop-filter: blur(16px);
      border-radius: var(--radius-lg);
    }}
    .hero {{
      padding: 32px 34px;
      display: grid;
      grid-template-columns: 1.6fr 1fr;
      gap: 24px;
      align-items: start;
    }}
    .eyebrow {{
      font-size: 12px;
      text-transform: uppercase;
      color: var(--accent);
      letter-spacing: 0.12em;
      margin-bottom: 8px;
      font-weight: 700;
    }}
    h1 {{
      margin: 0;
      font-size: 40px;
      line-height: 1.04;
    }}
    .lead {{
      color: #42506a;
      margin: 16px 0 0;
      max-width: 65ch;
      line-height: 1.65;
    }}
    .actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-top: 18px;
    }}
    .action {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 44px;
      padding: 0 16px;
      border-radius: 14px;
      text-decoration: none;
      font-weight: 700;
      border: 1px solid var(--accent);
      color: white;
      background: linear-gradient(135deg, var(--accent), #4f8df5);
      box-shadow: 0 14px 28px rgba(37, 99, 235, 0.24);
    }}
    .action.secondary {{
      background: var(--surface-strong);
      color: var(--accent);
    }}
    .hero-side {{
      background: linear-gradient(180deg, var(--panel), var(--surface-strong));
      border: 1px solid var(--border);
      padding: 20px;
      border-radius: var(--radius-md);
    }}
    .hero-side dl {{
      margin: 0;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px 12px;
    }}
    .hero-side dt {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .hero-side dd {{
      margin: 0;
      font-weight: 700;
      text-align: right;
    }}
    .bands {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 16px;
      margin-top: 16px;
    }}
    .band {{
      background: var(--surface-strong);
      border: 1px solid var(--border);
      padding: 20px;
      box-shadow: var(--shadow);
      border-radius: var(--radius-md);
    }}
    .band .label {{
      font-size: 12px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .band .value {{
      font-size: 30px;
      font-weight: 700;
      margin-top: 10px;
    }}
    .section {{
      margin-top: 18px;
      padding: 24px;
    }}
    .section h2 {{
      margin: 0 0 14px;
      font-size: 24px;
    }}
    .two-col {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 18px;
    }}
    .subpanel {{
      background: var(--panel);
      border: 1px solid var(--border);
      padding: 18px;
      border-radius: var(--radius-md);
    }}
    .subpanel h3 {{
      margin: 0 0 12px;
      font-size: 18px;
    }}
    ul {{
      margin: 0;
      padding-left: 18px;
    }}
    li {{
      margin-bottom: 10px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
      background: var(--surface-strong);
      border-radius: var(--radius-md);
      overflow: hidden;
    }}
    th, td {{
      padding: 12px 10px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
    }}
    th {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      background: var(--panel);
    }}
    .footer {{
      margin-top: 16px;
      color: var(--muted);
      font-size: 13px;
      text-align: center;
    }}
    @media (max-width: 900px) {{
      .hero, .two-col {{ grid-template-columns: 1fr; }}
      .bands {{ grid-template-columns: 1fr 1fr; }}
      h1 {{ font-size: 30px; }}
    }}
    @media (max-width: 640px) {{
      .page {{ padding: 14px; }}
      .hero, .section {{ padding: 18px; }}
      .bands {{ grid-template-columns: 1fr; }}
      .hero-side dl {{ grid-template-columns: 1fr; }}
      .hero-side dd {{ text-align: left; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <section class="hero">
      <div>
        <div class="eyebrow">ShieldCheck Self-Check Report</div>
        <h1>{self._escape(lead.company_name)}</h1>
        <p class="lead">{summary}</p>
        <div class="actions">
          {pdf_link}
        </div>
      </div>
      <aside class="hero-side">
        <dl>
          {profile_html}
        </dl>
      </aside>
    </section>

    <section class="bands">
      <div class="band">
        <div class="label">Assessment score</div>
        <div class="value">{lead.total_score:.1f}/{lead.max_score:.0f}</div>
      </div>
      <div class="band">
        <div class="label">Checks passed</div>
        <div class="value">{score_pct}%</div>
      </div>
      <div class="band">
        <div class="label">Items to review</div>
        <div class="value">{lead.findings_count}</div>
      </div>
      <div class="band">
        <div class="label">NIS2 applicability</div>
        <div class="value">{self._escape(self._nis2_short_label(lead))}</div>
      </div>
    </section>

    <section class="section">
      <h2>Assessment summary</h2>
      <div class="two-col">
        <div class="subpanel">
          <h3>Key issues</h3>
          <ul>{findings_html}</ul>
        </div>
        <div class="subpanel">
          <h3>Positive signals</h3>
          <ul>{positives_html}</ul>
        </div>
      </div>
    </section>

    <section class="section">
      <h2>Control-by-control view</h2>
      <table>
        <thead>
          <tr>
            <th>Dimension</th>
            <th>Score</th>
            <th>Assessment</th>
          </tr>
        </thead>
        <tbody>
          {detail_table}
        </tbody>
      </table>
    </section>

    <div class="footer">
      This self-check is based on public signals captured from the target domain and supporting public infrastructure.
    </div>
  </div>
</body>
</html>"""

    def _posture_label(self, lead: LeadScore) -> str:
        if not lead.max_score:
            return "Insufficient data"
        ratio = lead.total_score / lead.max_score
        if ratio <= 0.45:
            return "Needs attention"
        if ratio <= 0.75:
            return "Some improvements advised"
        return "Good baseline visible"

    def _nis2_summary(self, lead: LeadScore) -> str:
        if lead.nis2_covered:
            entity = lead.nis2_entity_type or "covered"
            sector = lead.nis2_sector or lead.sector
            if sector and sector != "Unknown":
                return f"Potentially in scope as a {entity} entity in {sector}"
            return f"Potentially in scope as a {entity} entity"
        return "No clear public signal that NIS2 applies"

    def _nis2_short_label(self, lead: LeadScore) -> str:
        if lead.nis2_covered:
            return "Potentially in scope"
        return "Not clearly indicated"

    def _owner_summary(self, lead: LeadScore) -> str:
        if lead.management_summary:
            text = lead.management_summary
        else:
            text = "This report summarizes externally visible security and NIS2 readiness signals."
        text = text.replace("security posture", "security setup")
        text = text.replace("posture", "setup")
        return self._escape(text)

    def _escape(self, value: str) -> str:
        return (
            str(value)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
