/* ═══════════════════════════════════════════════════════════════
   LEAD SCOUT WEB — Client-side application logic
   ═══════════════════════════════════════════════════════════════ */

// ─── State ───
let companies = [];
let results = [];
let eventSource = null;
let reportHtmlPath = null;
let pdfPaths = {};

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
            <td><button class="btn btn-ghost" style="padding:0.2rem 0.5rem;font-size:0.8rem" onclick="removeCompany(${i})">✕</button></td>
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
    companies.push({
      name,
      domain: domain.replace(/^https?:\/\//, "").replace(/\/$/, ""),
      sector,
      employees,
    });
    refreshCompanyTable();
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

async function removeCompany(idx) {
  await fetch(`/api/companies/${idx}`, { method: "DELETE" });
  companies.splice(idx, 1);
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
    admin_panel: "Admin Panel",
    security_hiring: "Security Hiring",
    security_governance: "Security Governance",
    security_communication: "Security Communication",
    nis2_readiness: "NIS2 Readiness",
  };

  const nis2 = r.nis2 || {};

  let html = `
        <div class="detail-grid">
            <div><div class="detail-item-label">Domain</div><div class="detail-item-value">${esc(r.domain)}</div></div>
            <div><div class="detail-item-label">Sector</div><div class="detail-item-value">${esc(r.sector)}</div></div>
            <div><div class="detail-item-label">Employees</div><div class="detail-item-value">${r.employees}</div></div>
            <div><div class="detail-item-label">Score</div><div class="detail-item-value">${r.total_score.toFixed(1)} / ${r.max_score}</div></div>
            <div><div class="detail-item-label">NIS2 Covered</div><div class="detail-item-value">${nis2.covered ? "Yes" : "No"}</div></div>
            <div><div class="detail-item-label">Compliance Priority</div><div class="detail-item-value">${esc(nis2.compliance_priority || "N/A")}</div></div>
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
    const val = s.score ?? "?";
    const emoji = val === 0 ? "🔴" : val === 1 ? "🟡" : "🟢";
    html += `<div class="score-row"><span>${emoji} ${label}</span><span class="score-val">${val}/2</span></div>`;
  }
  html += `</div>`;

  // Key gaps
  if (r.key_gaps && r.key_gaps.length) {
    html += `<div class="detail-section"><h4>Key Gaps</h4>`;
    r.key_gaps.forEach((g) => {
      html += `<div class="gap-item">⚠ ${esc(g)}</div>`;
    });
    html += `</div>`;
  }

  // Positive findings
  if (r.positive_findings && r.positive_findings.length) {
    html += `<div class="detail-section"><h4>Positive Findings</h4>`;
    r.positive_findings.forEach((p) => {
      html += `<div class="pos-item">✓ ${esc(p)}</div>`;
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
