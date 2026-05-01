/* ═══════════════════════════════════════════════════════════════
   LEAD SCOUT WEB — Client-side application logic
   ═══════════════════════════════════════════════════════════════ */

// ─── State ───
let companies = [];
let results = [];
let eventSource = null;
let reportHtmlPath = null;
let pdfPaths = {};
let scanHistoryPage = 1;
let domainListHistoryPage = 1;
const HISTORY_PAGE_SIZE = 10;
let confirmAction = null;

// ─── Clock ───
function updateClock() {
  const el = document.getElementById("clockDisplay");
  if (el) el.textContent = new Date().toLocaleString();
}
setInterval(updateClock, 1000);
updateClock();

// ─── Modals ───
function openModal(id) {
  document.getElementById(id).classList.add("active");
}
function closeModal(id) {
  document.getElementById(id).classList.remove("active");
}
function openAddModal() {
  openModal("addModal");
  document.getElementById("addName").focus();
}
function openUploadModal() {
  openModal("uploadModal");
}

function openConfirmModal({ title, message, okText, onOk }) {
  document.getElementById("confirmTitle").textContent = title || "Confirm";
  const body = document.getElementById("confirmBody");
  body.textContent = message || "";

  const okBtn = document.getElementById("confirmOkBtn");
  okBtn.disabled = false;
  okBtn.textContent = okText || "Confirm";

  confirmAction = async () => {
    okBtn.disabled = true;
    okBtn.textContent = "Working...";
    try {
      await onOk?.();
      closeModal("confirmModal");
    } finally {
      okBtn.disabled = false;
      okBtn.textContent = okText || "Confirm";
      confirmAction = null;
    }
  };

  okBtn.onclick = () => confirmAction?.();
  openModal("confirmModal");
}

// Close modals on overlay click
document.querySelectorAll(".modal-overlay").forEach((el) => {
  el.addEventListener("click", () => el.classList.remove("active"));
});

// ─── Company Management ───
function refreshCompanyTable() {
  const tbody = document.getElementById("companyBody");
  const empty = document.getElementById("companyEmpty");
  const count = document.getElementById("companyCount");

  tbody.innerHTML = "";
  count.textContent = companies.length;
  empty.style.display = companies.length ? "none" : "block";

  companies.forEach((c, i) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
            <td>${i + 1}</td>
            <td>${esc(c.name)}</td>
            <td>${esc(c.domain)}</td>
            <td>${esc(c.sector)}</td>
            <td>${c.employees}</td>
            <td><button class="btn btn-ghost" style="padding:0.2rem 0.5rem;font-size:0.8rem" onclick="removeCompany(${c.id})">✕</button></td>
        `;
    tbody.appendChild(tr);
  });
}

async function submitAddCompany() {
  const name = document.getElementById("addName").value.trim();
  const domain = document.getElementById("addDomain").value.trim();
  const sector = document.getElementById("addSector").value.trim() || "Unknown";
  const employees =
    parseInt(document.getElementById("addEmployees").value) || 100;

  if (!name || !domain) {
    alert("Name and domain are required.");
    return;
  }

  const res = await fetch("/api/companies", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, domain, sector, employees }),
  });
  const data = await res.json();
  if (data.ok) {
    await loadCompanies();
    closeModal("addModal");
    // Reset form
    document.getElementById("addName").value = "";
    document.getElementById("addDomain").value = "";
    document.getElementById("addSector").value = "Unknown";
    document.getElementById("addEmployees").value = "100";
  } else {
    alert(data.error || "Failed to add company");
  }
}

async function submitUpload() {
  const fileInput = document.getElementById("fileInput");
  if (!fileInput.files.length) {
    alert("Select a file first.");
    return;
  }

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);

  const res = await fetch("/api/upload", { method: "POST", body: formData });
  const data = await res.json();
  if (data.ok) {
    // Refresh from server
    await loadCompanies();
    closeModal("uploadModal");
    fileInput.value = "";
  } else {
    alert(data.error || "Upload failed");
  }
}

async function removeCompany(companyId) {
  await fetch(`/api/companies/${companyId}`, { method: "DELETE" });
  companies = companies.filter((c) => c.id !== companyId);
  refreshCompanyTable();
}

async function clearCompanies() {
  if (companies.length && !confirm("Clear all companies?")) return;
  await fetch("/api/companies", { method: "DELETE" });
  companies = [];
  refreshCompanyTable();
}

async function loadCompanies() {
  const res = await fetch("/api/companies");
  companies = await res.json();
  refreshCompanyTable();
}

// ─── History ───
function fmtDateTime(iso) {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return String(iso || "");
  }
}

function renderPager(el, page, pageSize, total, onPage) {
  const totalPages = Math.max(1, Math.ceil((total || 0) / pageSize));
  el.innerHTML = "";

  const prev = document.createElement("button");
  prev.className = "btn btn-ghost";
  prev.textContent = "Prev";
  prev.disabled = page <= 1;
  prev.onclick = () => onPage(page - 1);

  const next = document.createElement("button");
  next.className = "btn btn-ghost";
  next.textContent = "Next";
  next.disabled = page >= totalPages;
  next.onclick = () => onPage(page + 1);

  const info = document.createElement("span");
  info.className = "pager-info";
  info.textContent = `Page ${page} / ${totalPages}`;

  el.appendChild(prev);
  el.appendChild(next);
  el.appendChild(info);
}

function openHistoryReport(path) {
  if (path) window.open(path, "_blank");
}

async function loadScanHistory(page = scanHistoryPage) {
  scanHistoryPage = page;
  const res = await fetch(
    `/api/history/scans?page=${encodeURIComponent(page)}&page_size=${HISTORY_PAGE_SIZE}`,
  );
  const data = await res.json();

  const tbody = document.getElementById("scanHistoryBody");
  tbody.innerHTML = "";
  (data.items || []).forEach((r) => {
    const tr = document.createElement("tr");

    const tdDt = document.createElement("td");
    tdDt.textContent = fmtDateTime(r.created_at);

    const tdCnt = document.createElement("td");
    tdCnt.textContent = String(r.domain_count ?? "");

    const tdAct = document.createElement("td");
    const btn = document.createElement("button");
    btn.className = "btn btn-secondary";
    btn.style.padding = "0.35rem 0.7rem";
    btn.textContent = "Open";
    btn.onclick = () => openHistoryReport(r.report_html_path);
    tdAct.appendChild(btn);

    tr.appendChild(tdDt);
    tr.appendChild(tdCnt);
    tr.appendChild(tdAct);
    tbody.appendChild(tr);
  });

  renderPager(
    document.getElementById("scanHistoryPager"),
    data.page || page,
    data.page_size || HISTORY_PAGE_SIZE,
    data.total || 0,
    (p) => loadScanHistory(p),
  );
}

async function loadDomainListHistory(page = domainListHistoryPage) {
  domainListHistoryPage = page;
  const res = await fetch(
    `/api/history/domain-lists?page=${encodeURIComponent(page)}&page_size=${HISTORY_PAGE_SIZE}`,
  );
  const data = await res.json();

  const tbody = document.getElementById("domainListHistoryBody");
  tbody.innerHTML = "";
  (data.items || []).forEach((r) => {
    const tr = document.createElement("tr");

    const tdDt = document.createElement("td");
    tdDt.textContent = fmtDateTime(r.created_at);

    const tdCnt = document.createElement("td");
    tdCnt.textContent = String(r.domain_count ?? "");

    const tdAct = document.createElement("td");

    const btn = document.createElement("button");
    btn.className = "btn btn-secondary";
    btn.style.padding = "0.35rem 0.7rem";
    btn.textContent = "View";
    btn.onclick = () => viewDomainList(r.id);
    tdAct.appendChild(btn);

    const useBtn = document.createElement("button");
    useBtn.className = "btn btn-primary";
    useBtn.style.padding = "0.35rem 0.7rem";
    useBtn.style.marginLeft = "0.5rem";
    useBtn.textContent = "Use";
    useBtn.onclick = () => promptUseDomainList(r.id, r.domain_count);
    tdAct.appendChild(useBtn);

    tr.appendChild(tdDt);
    tr.appendChild(tdCnt);
    tr.appendChild(tdAct);
    tbody.appendChild(tr);
  });

  renderPager(
    document.getElementById("domainListHistoryPager"),
    data.page || page,
    data.page_size || HISTORY_PAGE_SIZE,
    data.total || 0,
    (p) => loadDomainListHistory(p),
  );
}

async function viewDomainList(domainListId) {
  const res = await fetch(`/api/history/domain-lists/${domainListId}`);
  const data = await res.json();
  const items = data.items || [];

  document.getElementById("detailTitle").textContent =
    `Domain List #${domainListId} (${items.length})`;

  let html =
    `<div class="table-wrap"><table class="data-table"><thead><tr><th>#</th><th>Company</th><th>Domain</th></tr></thead><tbody>`;
  items.forEach((it, i) => {
    html += `<tr><td>${i + 1}</td><td>${esc(it.name)}</td><td>${esc(it.domain)}</td></tr>`;
  });
  html += `</tbody></table></div>`;

  document.getElementById("detailBody").innerHTML = html;
  openModal("detailModal");
}

function promptUseDomainList(domainListId, domainCount) {
  openConfirmModal({
    title: "Use Domain List",
    message:
      `This will replace your current Companies to Scan list with Domain List #${domainListId} ` +
      `(${domainCount ?? "?"} domains). Continue?`,
    okText: "Use List",
    onOk: () => useDomainListNow(domainListId),
  });
}

async function useDomainListNow(domainListId) {
  const res = await fetch(`/api/history/domain-lists/${domainListId}/use`, {
    method: "POST",
  });
  const data = await res.json();
  if (!data.ok) {
    alert(data.error || "Failed to use domain list");
    return;
  }

  await loadCompanies();
  await loadDomainListHistory(domainListHistoryPage);
}

// ─── Scanning ───
async function startScan() {
  if (!companies.length) {
    alert("Add companies first.");
    return;
  }

  const timeout = parseFloat(document.getElementById("cfgTimeout").value) || 8;
  const delay = parseFloat(document.getElementById("cfgDelay").value) || 1;
  const verbose = document.getElementById("cfgVerbose").checked;

  results = [];
  reportHtmlPath = null;
  document.getElementById("resultsBody").innerHTML = "";
  document.getElementById("logBox").textContent = "";
  document.getElementById("progressBar").style.width = "0%";

  const res = await fetch("/api/scan/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ timeout, delay, verbose }),
  });
  const data = await res.json();
  if (!data.ok) {
    alert(data.error || "Failed to start scan");
    return;
  }

  // Show sections
  show("progressSection");
  show("statsSection");
  show("resultsSection");
  show("logSection");

  document.getElementById("btnStartScan").disabled = true;
  document.getElementById("btnStopScan").disabled = false;
  document.getElementById("btnOpenReport").style.display = "none";

  startEventStream();
}

async function stopScan() {
  await fetch("/api/scan/stop", { method: "POST" });
  document.getElementById("btnStopScan").disabled = true;
}

function startEventStream() {
  if (eventSource) eventSource.close();
  eventSource = new EventSource("/api/scan/stream");

  eventSource.onmessage = (event) => {
    const data = JSON.parse(event.data);
    updateProgress(data);
    updateResults(data.results);
    appendLogs(data.new_logs);

    if (data.report_html) {
      reportHtmlPath = data.report_html;
      document.getElementById("btnOpenReport").style.display = "";
    }

    if (data.pdf_paths) {
      pdfPaths = data.pdf_paths;
    }

    if (!data.running) {
      eventSource.close();
      eventSource = null;
      document.getElementById("btnStartScan").disabled = false;
      document.getElementById("btnStopScan").disabled = true;
      loadScanHistory(1);
      loadDomainListHistory(1);
    }
  };

  eventSource.onerror = () => {
    eventSource.close();
    eventSource = null;
    document.getElementById("btnStartScan").disabled = false;
    document.getElementById("btnStopScan").disabled = true;
  };
}

function updateProgress(data) {
  const pct = data.total ? Math.round((data.progress / data.total) * 100) : 0;
  document.getElementById("progressBar").style.width = pct + "%";
  document.getElementById("progressText").textContent =
    `${data.progress} / ${data.total}` +
    (data.current_company ? `  —  ${data.current_company}` : "");
}

function updateResults(newResults) {
  results = newResults;
  const tbody = document.getElementById("resultsBody");
  tbody.innerHTML = "";

  let hot = 0,
    warm = 0,
    cool = 0;

  results.forEach((r, i) => {
    const tierClass = r.tier.includes("HOT")
      ? "hot"
      : r.tier.includes("WARM")
        ? "warm"
        : "cool";
    if (tierClass === "hot") hot++;
    else if (tierClass === "warm") warm++;
    else cool++;

    const hasPdf = pdfPaths[r.domain];
    const tr = document.createElement("tr");
    tr.innerHTML = `
            <td>${i + 1}</td>
            <td><span class="tier tier-${tierClass}">${esc(r.tier)}</span></td>
            <td>${esc(r.company_name)}</td>
            <td>${esc(r.domain)}</td>
            <td>${r.total_score.toFixed(1)} / ${r.max_score}</td>
            <td>${r.findings_count}</td>
            <td>${esc(r.sector)}</td>
            <td>
                ${hasPdf ? `<button class="btn btn-ghost" style="padding:0.2rem 0.5rem;font-size:0.8rem" onclick="downloadPdf('${esc(r.domain)}')" title="Download PDF">📄</button>` : ""}
                <button class="btn btn-detail" onclick="showDetail(${i})">Details</button>
            </td>
        `;
    tbody.appendChild(tr);
  });

  document.getElementById("statTotal").textContent = results.length;
  document.getElementById("statHot").textContent = hot;
  document.getElementById("statWarm").textContent = warm;
  document.getElementById("statCool").textContent = cool;
}

function appendLogs(lines) {
  if (!lines || !lines.length) return;
  const box = document.getElementById("logBox");
  box.textContent += lines.join("\n") + "\n";
  box.scrollTop = box.scrollHeight;
}

// ─── Detail View ───
function showDetail(idx) {
  const r = results[idx];
  if (!r) return;

  document.getElementById("detailTitle").textContent =
    `${r.company_name} — ${r.tier}`;

  const dimensionLabels = {
    email_security: "Email Security",
    technical_hygiene: "Technical Hygiene",
    tls_certificate: "TLS Certificate",
    http_headers: "HTTP Headers",
    cookie_compliance: "Cookie Compliance",
    attack_surface: "Attack Surface",
    tech_stack: "Tech Stack",
    admin_panel: "Admin Exposure",
    security_hiring: "Security Hiring",
    security_governance: "Security Governance",
  };

  let html = `
        <div class="detail-grid">
            <div><div class="detail-item-label">Domain</div><div class="detail-item-value">${esc(r.domain)}</div></div>
            <div><div class="detail-item-label">Sector</div><div class="detail-item-value">${esc(r.sector)}</div></div>
            <div><div class="detail-item-label">Employees</div><div class="detail-item-value">${r.employees}</div></div>
            <div><div class="detail-item-label">Score</div><div class="detail-item-value">${r.total_score.toFixed(1)} / ${r.max_score}</div></div>
        </div>
    `;

  if (r.management_summary) {
    html += `<div class="detail-section"><h4>Management Summary</h4><p style="font-size:0.88rem;color:var(--text-secondary)">${esc(r.management_summary)}</p></div>`;
  }

  // Score breakdown
  html += `<div class="detail-section"><h4>Score Breakdown</h4>`;
  const scores = r.scores || {};
  for (const [key, label] of Object.entries(dimensionLabels)) {
    const s = scores[key] || {};
    const analyzed = typeof s.score === "number" && typeof s.max_score === "number";
    const scoreText = analyzed ? `${s.score}/${s.max_score}` : "N/A";

    // In the popup we highlight "missing points" as orange (e.g. 2/3),
    // even if the percentage would otherwise be green.
    let status = "unknown";
    if (analyzed) {
      status = s.score === 0 ? "risk" : s.score < s.max_score ? "warning" : "ok";
    }
    html += `<div class="score-row"><span><span class="indicator indicator-${status}"></span>${label}</span><span class="score-val">${scoreText}</span></div>`;
  }
  html += `</div>`;

  // Key gaps
  if (r.key_gaps && r.key_gaps.length) {
    html += `<div class="detail-section"><h4>Key Gaps</h4>`;
    r.key_gaps.forEach((g) => {
      html += `<div class="gap-item gap-key">⚠ ${esc(g)}</div>`;
    });
    html += `</div>`;
  }

  // Sales angles
  if (r.sales_angles && r.sales_angles.length) {
    html += `<div class="detail-section"><h4>Sales Angles</h4>`;
    r.sales_angles.forEach((s) => {
      html += `<div class="sales-item">→ ${esc(s)}</div>`;
    });
    html += `</div>`;
  }

  // Recommendations (present vs missing, color-coded)
  const dimensionSummaries = [];
  for (const [key, label] of Object.entries(dimensionLabels)) {
    const s = scores[key] || {};
    const analyzed = typeof s.score === "number" && typeof s.max_score === "number";
    if (!analyzed) continue;

    const present = Array.isArray(s.present) ? s.present : [];
    const missing = Array.isArray(s.missing) ? s.missing : [];
    const risks = Array.isArray(s.risks) ? s.risks : [];

    if (!present.length && !missing.length && !risks.length) continue;
    dimensionSummaries.push({ label, present, missing, risks });
  }

  if (dimensionSummaries.length) {
    html += `<div class="detail-section"><h4>Recommendations</h4>`;
    dimensionSummaries.forEach((d) => {
      html += `<div style="margin:0.6rem 0 0.2rem 0;font-weight:600">${esc(d.label)}</div>`;
      d.present.forEach((p) => {
        html += `<div class="pos-item rec-present">✓ ${esc(p)}</div>`;
      });
      d.missing.forEach((m) => {
        html += `<div class="gap-item rec-missing">✕ ${esc(m)}</div>`;
      });
      if (d.risks.length) {
        html += `<div class="risk-item rec-risk">Risk: ${esc(d.risks[0])}</div>`;
      }
    });
    html += `</div>`;
  }

  // PDF download button
  if (pdfPaths[r.domain]) {
    html += `<div class="detail-section" style="text-align:center;margin-top:1rem">
      <button class="btn btn-primary" onclick="downloadPdf('${esc(r.domain)}')">📄 Download PDF Report</button>
    </div>`;
  }

  document.getElementById("detailBody").innerHTML = html;
  openModal("detailModal");
}

// ─── Export / Reports ───
function openReport() {
  if (reportHtmlPath) window.open(reportHtmlPath, "_blank");
}

function downloadPdf(domain) {
  window.open(`/api/pdf/${encodeURIComponent(domain)}`, "_blank");
}

function exportJSON() {
  if (!results.length) {
    alert("No results to export.");
    return;
  }
  const blob = new Blob(
    [
      JSON.stringify(
        { generated_at: new Date().toISOString(), leads: results },
        null,
        2,
      ),
    ],
    { type: "application/json" },
  );
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `lead_scout_export_${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Helpers ───
function show(id) {
  document.getElementById(id).style.display = "";
}
function hide(id) {
  document.getElementById(id).style.display = "none";
}

function esc(str) {
  if (str == null) return "";
  const d = document.createElement("div");
  d.appendChild(document.createTextNode(String(str)));
  return d.innerHTML;
}

// ─── Keyboard shortcuts ───
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    document
      .querySelectorAll(".modal-overlay.active")
      .forEach((m) => m.classList.remove("active"));
  }
});

// ─── Init ───
loadCompanies();
loadScanHistory();
loadDomainListHistory();
