let accountSummary = null;
let companies = [];
let results = [];
let eventSource = null;
let reportHtmlPath = null;
let pdfPaths = {};
let scanHistoryPage = 1;
let domainListHistoryPage = 1;
const HISTORY_PAGE_SIZE = 10;
let confirmAction = null;
let appMode = "account";
let selectedPlatformAccountId = null;

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
  document.getElementById("confirmBody").textContent = message || "";

  const okBtn = document.getElementById("confirmOkBtn");
  okBtn.textContent = okText || "Confirm";
  okBtn.disabled = false;

  confirmAction = async () => {
    okBtn.disabled = true;
    try {
      await onOk?.();
      closeModal("confirmModal");
    } finally {
      okBtn.disabled = false;
      confirmAction = null;
    }
  };
  okBtn.onclick = () => confirmAction?.();
  openModal("confirmModal");
}

document.querySelectorAll(".modal-overlay").forEach((el) => {
  el.addEventListener("click", () => el.classList.remove("active"));
});

function esc(str) {
  if (str == null) return "";
  const d = document.createElement("div");
  d.appendChild(document.createTextNode(String(str)));
  return d.innerHTML;
}

function fmtDateTime(iso) {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return String(iso || "");
  }
}

function fmtFeatureValue(value) {
  if (value === true) return "Yes";
  if (value === false) return "No";
  if (value == null || value === "") return "-";
  return String(value).replaceAll("_", " ");
}

function tierClassFor(tier) {
  const t = String(tier || "").toUpperCase();
  if (t.includes("HOT")) return "hot";
  if (t.includes("WARM")) return "warm";
  return "cool";
}

function toLocalDateTimeInput(isoValue) {
  if (!isoValue) return "";
  const date = new Date(isoValue);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (v) => String(v).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

async function apiJson(url, options = {}) {
  const res = await fetch(url, options);
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || "Request failed");
  }
  return data;
}

function setSectionVisibility(id, visible) {
  const el = document.getElementById(id);
  if (el) el.style.display = visible ? "" : "none";
}

function hideAccountWorkspace() {
  ["scanningSection", "historySection", "overviewSection", "adminSection"].forEach((id) =>
    setSectionVisibility(id, false),
  );
}

function showAccountWorkspace() {
  ["scanningSection", "historySection"].forEach((id) =>
    setSectionVisibility(id, true),
  );
}

async function loadAccountSummary() {
  accountSummary = await apiJson("/api/account/summary");
  appMode = accountSummary.mode || "account";

  if (appMode === "platform_admin") {
    setSectionVisibility("platformSection", true);
    hideAccountWorkspace();
    await loadPlatformAccounts();
    return;
  }

  setSectionVisibility("platformSection", false);
  showAccountWorkspace();

  const isAdmin = accountSummary.viewer.role === "admin";
  setSectionVisibility("overviewSection", isAdmin);
  setSectionVisibility("adminSection", isAdmin);

  if (isAdmin) {
    document.getElementById("accountMeta").textContent =
      `${accountSummary.account_name} - ${accountSummary.viewer.username} (${accountSummary.viewer.role})`;
    document.getElementById("planName").textContent = accountSummary.plan_name;
    document.getElementById("billingCycle").textContent =
      `${accountSummary.billing_cycle} billing`;
    document.getElementById("userUsage").textContent =
      `${accountSummary.user_count} / ${accountSummary.max_users}`;
    document.getElementById("monthlyAllocation").textContent =
      `${accountSummary.monthly_tokens} tokens`;
    document.getElementById("refreshAt").textContent =
      `Refreshes ${fmtDateTime(accountSummary.next_token_refresh_at)}`;
    document.getElementById("subscriptionStatus").textContent =
      accountSummary.subscription_status;

    document.getElementById("balanceTotal").textContent =
      accountSummary.token_balances.total;
    document.getElementById("balanceMonthly").textContent =
      accountSummary.token_balances.monthly;
    document.getElementById("balancePurchased").textContent =
      accountSummary.token_balances.purchased;
    document.getElementById("balanceGranted").textContent =
      accountSummary.token_balances.granted;

    renderFeatures(accountSummary.features || {});
    await loadTokenLedger();
    await loadUsers();
  }
}

async function loadPlatformAccounts() {
  const items = await apiJson("/api/platform/accounts");
  const tbody = document.getElementById("platformAccountsBody");
  tbody.innerHTML = "";
  items.forEach((item) => {
    const tr = document.createElement("tr");
    tr.className = "clickable-row";
    tr.dataset.accountId = String(item.account_id);
    tr.onclick = () => selectPlatformAccount(item.account_id);
    tr.innerHTML = `
      <td>${esc(item.account_name)}</td>
      <td>${esc(item.plan_name)}</td>
      <td>${esc(item.billing_cycle)}</td>
      <td>${item.user_count} / ${item.max_users}</td>
      <td>${item.token_balances.total}</td>
      <td>${fmtDateTime(item.next_token_refresh_at)}</td>
    `;
    tbody.appendChild(tr);
  });
  if (selectedPlatformAccountId) {
    document.querySelectorAll("#platformAccountsBody tr").forEach((row) => {
      row.classList.toggle("selected-row", row.dataset.accountId === String(selectedPlatformAccountId));
    });
  }
}

async function selectPlatformAccount(accountId) {
  selectedPlatformAccountId = accountId;
  const account = await apiJson(`/api/platform/accounts/${accountId}`);
  document.querySelectorAll("#platformAccountsBody tr").forEach((row) => {
    row.classList.toggle("selected-row", row.dataset.accountId === String(accountId));
  });
  document.getElementById("platformModalTitle").textContent = account.account_name;
  document.getElementById("platformModalMeta").textContent =
    `${account.plan_name} - ${account.subscription_status} - refresh ${fmtDateTime(account.next_token_refresh_at)}`;
  document.getElementById("platformBalanceTotal").textContent = account.token_balances.total;
  document.getElementById("platformBalanceMonthly").textContent = account.token_balances.monthly;
  document.getElementById("platformBalancePurchased").textContent = account.token_balances.purchased;
  document.getElementById("platformBalanceGranted").textContent = account.token_balances.granted;
  document.getElementById("platformPlanCode").value = account.plan_code;
  document.getElementById("platformBillingCycleInput").value = account.billing_cycle;
  document.getElementById("platformSubscriptionStatusInput").value = account.subscription_status;
  document.getElementById("platformRefreshInput").value = toLocalDateTimeInput(account.next_token_refresh_at);
  renderPlatformUsers(account.users || []);
  renderPlatformLedger(account.token_ledger || []);
  renderPlatformAudit(account.admin_audit_log || []);
  openModal("platformAccountModal");
}

function renderPlatformUsers(users) {
  const container = document.getElementById("platformUsersList");
  container.innerHTML = "";
  if (!users.length) {
    container.innerHTML = `<div class="empty-msg compact-empty">No users found for this account.</div>`;
    return;
  }
  users.forEach((user) => {
    const row = document.createElement("div");
    row.className = "activity-item";
    row.innerHTML = `
      <div>
        <div>${esc(user.username)}</div>
        <div class="activity-meta">${esc(user.role)} - ${user.is_active ? "active" : "inactive"} - updated ${fmtDateTime(user.updated_at)}</div>
      </div>
    `;
    container.appendChild(row);
  });
}

function renderPlatformLedger(items) {
  const container = document.getElementById("platformLedgerList");
  container.innerHTML = "";
  if (!items.length) {
    container.innerHTML = `<div class="empty-msg compact-empty">No token activity yet.</div>`;
    return;
  }
  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "activity-item";
    const deltaClass = item.token_delta >= 0 ? "positive" : "negative";
    row.innerHTML = `
      <div>
        <div>${esc(item.description)}</div>
        <div class="activity-meta">${esc(item.username || "system")} - ${fmtDateTime(item.created_at)}</div>
      </div>
      <div class="token-delta ${deltaClass}">${item.token_delta > 0 ? "+" : ""}${item.token_delta}</div>
    `;
    container.appendChild(row);
  });
}

function renderPlatformAudit(items) {
  const container = document.getElementById("platformAuditList");
  container.innerHTML = "";
  if (!items.length) {
    container.innerHTML = `<div class="empty-msg compact-empty">No admin actions recorded yet.</div>`;
    return;
  }
  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "activity-item";
    const metaParts = [esc(item.username || "system"), fmtDateTime(item.created_at)];
    const changeCount = Object.keys(item.metadata?.changed_fields || {}).length;
    row.innerHTML = `
      <div>
        <div>${esc(item.description)}</div>
        <div class="activity-meta">${metaParts.join(" - ")}${changeCount ? ` - ${changeCount} field${changeCount === 1 ? "" : "s"} changed` : ""}</div>
      </div>
      <div class="activity-tag">${esc(item.event_type)}</div>
    `;
    container.appendChild(row);
  });
}

async function refreshSelectedPlatformAccount() {
  if (!selectedPlatformAccountId) return;
  await loadPlatformAccounts();
  await selectPlatformAccount(selectedPlatformAccountId);
}

async function savePlatformAccountSettings() {
  if (!selectedPlatformAccountId) {
    alert("Select an account first.");
    return;
  }
  const refreshValue = document.getElementById("platformRefreshInput").value;
  const payload = {
    plan_code: document.getElementById("platformPlanCode").value,
    billing_cycle: document.getElementById("platformBillingCycleInput").value,
    subscription_status: document.getElementById("platformSubscriptionStatusInput").value,
    next_token_refresh_at: refreshValue ? new Date(refreshValue).toISOString() : null,
  };
  try {
    await apiJson(`/api/platform/accounts/${selectedPlatformAccountId}/settings`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    await refreshSelectedPlatformAccount();
  } catch (error) {
    alert(error.message);
  }
}

async function grantPlatformTokens() {
  if (!selectedPlatformAccountId) {
    alert("Select an account first.");
    return;
  }
  const tokenCount = parseInt(document.getElementById("platformGrantTokenCount").value, 10);
  const note = document.getElementById("platformGrantTokenNote").value.trim();
  if (!tokenCount) {
    alert("Enter a token count.");
    return;
  }
  try {
    await apiJson(`/api/platform/accounts/${selectedPlatformAccountId}/grant-tokens`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token_count: tokenCount, note }),
    });
    document.getElementById("platformGrantTokenCount").value = "";
    document.getElementById("platformGrantTokenNote").value = "";
    await refreshSelectedPlatformAccount();
  } catch (error) {
    alert(error.message);
  }
}

async function removePlatformTokens() {
  if (!selectedPlatformAccountId) {
    alert("Select an account first.");
    return;
  }
  const tokenCount = parseInt(document.getElementById("platformRemoveTokenCount").value, 10);
  const note = document.getElementById("platformRemoveTokenNote").value.trim();
  if (!tokenCount) {
    alert("Enter a token count.");
    return;
  }
  openConfirmModal({
    title: "Remove Tokens",
    message: `Remove ${tokenCount} token${tokenCount === 1 ? "" : "s"} from this account?`,
    okText: "Remove",
    onOk: async () => {
      await apiJson(`/api/platform/accounts/${selectedPlatformAccountId}/remove-tokens`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token_count: tokenCount, note }),
      });
      document.getElementById("platformRemoveTokenCount").value = "";
      document.getElementById("platformRemoveTokenNote").value = "";
      await refreshSelectedPlatformAccount();
    },
  });
}

async function forcePlatformRefreshNow() {
  if (!selectedPlatformAccountId) {
    alert("Select an account first.");
    return;
  }
  openConfirmModal({
    title: "Refresh Tokens Now",
    message: "This will apply the token refresh cycle immediately for the selected account.",
    okText: "Refresh Now",
    onOk: async () => {
      await apiJson(`/api/platform/accounts/${selectedPlatformAccountId}/refresh-now`, {
        method: "POST",
      });
      await refreshSelectedPlatformAccount();
    },
  });
}

function renderFeatures(features) {
  const labels = {
    domain_scan: "Domain scan",
    cybersecurity_lead_score: "Cybersecurity lead score",
    clear_explanation_of_findings: "Clear explanation of findings",
    basic_scan_history: "Basic scan history",
    basic_pdf_report: "Basic PDF report",
    csv_export: "CSV export",
    filter_sorting: "Filter and sorting",
    conversation_starter: "Conversation starter",
    lead_notes: "Lead notes",
    follow_up_status: "Follow-up status",
    scan_comparison: "Scan comparison",
    crm_integration: "CRM integration",
    api_access: "API access",
    two_level_reporting: "Two-level reporting",
    advanced_filters: "Advanced filters",
    advanced_sales_advice: "Advanced sales advice",
    white_label_reports: "White-label reports",
    custom_scoring_model: "Custom scoring model",
    custom_report_templates: "Custom report templates",
    priority_support: "Priority support",
    onboarding_support_package: "Onboarding/support package",
    lead_potential_ranking: "Lead potential ranking",
    export_options: "Export options",
    team_usage: "Team usage",
    custom_scan_volume: "Custom scan volume",
  };

  const container = document.getElementById("featureList");
  container.innerHTML = "";
  Object.entries(labels).forEach(([key, label]) => {
    const value = features[key];
    if (value == null) return;
    const item = document.createElement("div");
    item.className = "feature-item";
    item.innerHTML = `<span>${label}</span><strong>${esc(fmtFeatureValue(value))}</strong>`;
    container.appendChild(item);
  });
}

async function loadTokenLedger() {
  if (appMode !== "account") return;
  const items = await apiJson("/api/account/token-ledger");
  const box = document.getElementById("tokenLedger");
  box.innerHTML = "";
  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "activity-item";
    const deltaClass = item.token_delta >= 0 ? "positive" : "negative";
    row.innerHTML = `
      <div>
        <div>${esc(item.description)}</div>
        <div class="activity-meta">${esc(item.username || "system")} - ${fmtDateTime(item.created_at)}</div>
      </div>
      <div class="token-delta ${deltaClass}">${item.token_delta > 0 ? "+" : ""}${item.token_delta}</div>
    `;
    box.appendChild(row);
  });
}

async function loadUsers() {
  if (appMode !== "account") return;
  const users = await apiJson("/api/account/users");
  const tbody = document.getElementById("userBody");
  tbody.innerHTML = "";
  users.forEach((user) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${esc(user.username)}</td>
      <td>${esc(user.role)}</td>
      <td>${fmtDateTime(user.updated_at)}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function createUser() {
  const username = document.getElementById("newUsername").value.trim();
  const password = document.getElementById("newPassword").value;
  const role = document.getElementById("newRole").value;
  if (!username || !password) {
    alert("Username and password are required.");
    return;
  }
  try {
    await apiJson("/api/account/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, role }),
    });
    document.getElementById("newUsername").value = "";
    document.getElementById("newPassword").value = "";
    document.getElementById("newRole").value = "member";
    await loadAccountSummary();
  } catch (error) {
    alert(error.message);
  }
}

function filteredCompanies() {
  const query = document.getElementById("companySearch").value.trim().toLowerCase();
  if (!query) return companies;
  return companies.filter((company) =>
    [company.name, company.domain, company.sector].some((value) =>
      String(value || "").toLowerCase().includes(query),
    ),
  );
}

function refreshCompanyTable() {
  const tbody = document.getElementById("companyBody");
  const empty = document.getElementById("companyEmpty");
  const count = document.getElementById("companyCount");

  const visible = filteredCompanies();
  tbody.innerHTML = "";
  count.textContent = companies.length;
  empty.style.display = visible.length ? "none" : "block";

  visible.forEach((company, index) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${index + 1}</td>
      <td>${esc(company.name)}</td>
      <td>${esc(company.domain)}</td>
      <td>${esc(company.sector)}</td>
      <td>${company.employees}</td>
      <td><button class="btn btn-ghost compact-btn" onclick="removeCompany(${company.id})">x</button></td>
    `;
    tbody.appendChild(tr);
  });
}

async function loadCompanies() {
  if (appMode !== "account") return;
  companies = await apiJson("/api/companies");
  refreshCompanyTable();
}

async function submitAddCompany() {
  const name = document.getElementById("addName").value.trim();
  const domain = document.getElementById("addDomain").value.trim();
  const sector = document.getElementById("addSector").value.trim() || "Unknown";
  const employees = parseInt(document.getElementById("addEmployees").value, 10) || 100;
  if (!name || !domain) {
    alert("Name and domain are required.");
    return;
  }
  try {
    await apiJson("/api/companies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, domain, sector, employees }),
    });
    await loadCompanies();
    closeModal("addModal");
    document.getElementById("addName").value = "";
    document.getElementById("addDomain").value = "";
    document.getElementById("addSector").value = "Unknown";
    document.getElementById("addEmployees").value = "100";
  } catch (error) {
    alert(error.message);
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
  try {
    await apiJson("/api/upload", { method: "POST", body: formData });
    await loadCompanies();
    closeModal("uploadModal");
    fileInput.value = "";
  } catch (error) {
    alert(error.message);
  }
}

async function removeCompany(companyId) {
  await fetch(`/api/companies/${companyId}`, { method: "DELETE" });
  companies = companies.filter((company) => company.id !== companyId);
  refreshCompanyTable();
}

async function clearCompanies() {
  if (companies.length === 0) return;
  openConfirmModal({
    title: "Clear Companies",
    message: "This removes the current shared company list for the account.",
    okText: "Clear",
    onOk: async () => {
      await fetch("/api/companies", { method: "DELETE" });
      companies = [];
      refreshCompanyTable();
    },
  });
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
  if (appMode !== "account") return;
  scanHistoryPage = page;
  const data = await apiJson(
    `/api/history/scans?page=${encodeURIComponent(page)}&page_size=${HISTORY_PAGE_SIZE}`,
  );
  const tbody = document.getElementById("scanHistoryBody");
  tbody.innerHTML = "";
  (data.items || []).forEach((item) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${fmtDateTime(item.created_at)}</td>
      <td>${item.domain_count ?? ""}</td>
      <td><button class="btn btn-secondary compact-btn" onclick="openHistoryReport('${esc(item.report_html_path)}')">Open</button></td>
    `;
    tbody.appendChild(tr);
  });
  renderPager(
    document.getElementById("scanHistoryPager"),
    data.page || page,
    data.page_size || HISTORY_PAGE_SIZE,
    data.total || 0,
    (nextPage) => loadScanHistory(nextPage),
  );
}

async function loadDomainListHistory(page = domainListHistoryPage) {
  if (appMode !== "account") return;
  domainListHistoryPage = page;
  const data = await apiJson(
    `/api/history/domain-lists?page=${encodeURIComponent(page)}&page_size=${HISTORY_PAGE_SIZE}`,
  );
  const tbody = document.getElementById("domainListHistoryBody");
  tbody.innerHTML = "";
  (data.items || []).forEach((item) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${fmtDateTime(item.created_at)}</td>
      <td>${item.domain_count ?? ""}</td>
      <td>
        <button class="btn btn-secondary compact-btn" onclick="viewDomainList(${item.id})">View</button>
        <button class="btn btn-primary compact-btn" onclick="promptUseDomainList(${item.id}, ${item.domain_count || 0})">Use</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
  renderPager(
    document.getElementById("domainListHistoryPager"),
    data.page || page,
    data.page_size || HISTORY_PAGE_SIZE,
    data.total || 0,
    (nextPage) => loadDomainListHistory(nextPage),
  );
}

async function viewDomainList(domainListId) {
  const data = await apiJson(`/api/history/domain-lists/${domainListId}`);
  const items = data.items || [];
  document.getElementById("detailTitle").textContent =
    `Domain List #${domainListId} (${items.length})`;
  let html =
    `<div class="table-wrap"><table class="data-table"><thead><tr><th>#</th><th>Company</th><th>Domain</th><th>Sector</th></tr></thead><tbody>`;
  items.forEach((item, index) => {
    html += `<tr><td>${index + 1}</td><td>${esc(item.name)}</td><td>${esc(item.domain)}</td><td>${esc(item.sector)}</td></tr>`;
  });
  html += "</tbody></table></div>";
  document.getElementById("detailBody").innerHTML = html;
  openModal("detailModal");
}

function promptUseDomainList(domainListId, domainCount) {
  openConfirmModal({
    title: "Use Domain List",
    message: `Replace the current shared company list with Domain List #${domainListId} (${domainCount} domains)?`,
    okText: "Use List",
    onOk: async () => {
      await apiJson(`/api/history/domain-lists/${domainListId}/use`, { method: "POST" });
      await loadCompanies();
    },
  });
}

async function startScan() {
  if (appMode !== "account") return;
  if (!companies.length) {
    alert("Add companies first.");
    return;
  }
  const timeout = parseFloat(document.getElementById("cfgTimeout").value) || 8;
  const delay = parseFloat(document.getElementById("cfgDelay").value) || 1;
  const verbose = document.getElementById("cfgVerbose").checked;

  results = [];
  reportHtmlPath = null;
  pdfPaths = {};
  document.getElementById("resultsBody").innerHTML = "";
  document.getElementById("logBox").textContent = "";
  document.getElementById("progressBar").style.width = "0%";

  try {
    const data = await apiJson("/api/scan/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ timeout, delay, verbose }),
    });
    setSectionVisibility("progressSection", true);
    setSectionVisibility("statsSection", true);
    setSectionVisibility("resultsSection", true);
    setSectionVisibility("logSection", true);
    document.getElementById("btnStartScan").disabled = true;
    document.getElementById("btnStopScan").disabled = false;
    document.getElementById("btnOpenReport").style.display = "none";
    if (data.token_balances) {
      await loadAccountSummary();
    }
    startEventStream();
  } catch (error) {
    alert(error.message);
  }
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
      loadAccountSummary();
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
  document.getElementById("progressBar").style.width = `${pct}%`;
  document.getElementById("progressText").textContent =
    `${data.progress} / ${data.total}` +
    (data.current_company ? ` - ${data.current_company}` : "");
}

function filteredResults() {
  const query = document.getElementById("resultSearch").value.trim().toLowerCase();
  const sort = document.getElementById("resultSort").value;
  let visible = [...results];

  if (query) {
    visible = visible.filter((result) =>
      [result.company_name, result.domain, result.sector, result.follow_up_status].some((value) =>
        String(value || "").toLowerCase().includes(query),
      ),
    );
  }

  if (sort === "scoreAsc") {
    visible.sort((a, b) => a.total_score - b.total_score);
  } else if (sort === "scoreDesc") {
    visible.sort((a, b) => b.total_score - a.total_score);
  } else if (sort === "companyAsc") {
    visible.sort((a, b) => String(a.company_name).localeCompare(String(b.company_name)));
  }
  return visible;
}

function updateResults(newResults) {
  results = newResults;
  const tbody = document.getElementById("resultsBody");
  tbody.innerHTML = "";

  let hot = 0;
  let warm = 0;
  let cool = 0;

  filteredResults().forEach((result, index) => {
    const tierClass = tierClassFor(result.tier);
    if (tierClass === "hot") hot += 1;
    else if (tierClass === "warm") warm += 1;
    else cool += 1;

    const hasPdf = pdfPaths[result.domain];
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${index + 1}</td>
      <td><span class="tier tier-${tierClass}">${esc(result.tier)}</span></td>
      <td>${esc(result.company_name)}</td>
      <td>${esc(result.domain)}</td>
      <td>${result.total_score.toFixed(1)} / ${result.max_score}</td>
      <td>${result.findings_count}</td>
      <td>${esc(result.follow_up_status || "new")}</td>
      <td>
        ${hasPdf ? `<button class="btn btn-ghost compact-btn" onclick="downloadPdf('${encodeURIComponent(result.domain)}')">PDF</button>` : ""}
        <button class="btn btn-detail" onclick="showDetail('${encodeURIComponent(result.domain)}')">Details</button>
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
  box.textContent += `${lines.join("\n")}\n`;
  box.scrollTop = box.scrollHeight;
}

async function showDetail(encodedDomain) {
  const domain = decodeURIComponent(encodedDomain);
  const result = results.find((item) => item.domain === domain);
  if (!result) return;

  const noteData = await apiJson(`/api/lead-notes/${encodeURIComponent(domain)}`);
  result.lead_notes = noteData.notes || "";
  result.follow_up_status = noteData.follow_up_status || "new";

  document.getElementById("detailTitle").textContent =
    `${result.company_name} - ${result.tier}`;

  const dimensionLabels = {
    email_security: "Email Security",
    technical_hygiene: "Technical Hygiene",
    tls_certificate: "TLS Certificate",
    http_headers: "HTTP Headers",
    cookie_compliance: "Cookie Compliance",
    attack_surface: "Attack Surface",
    tech_stack: "Tech Stack",
    admin_panel: "Admin Exposure",
  };

  let html = `
    <div class="detail-grid">
      <div><div class="detail-item-label">Domain</div><div class="detail-item-value">${esc(result.domain)}</div></div>
      <div><div class="detail-item-label">Sector</div><div class="detail-item-value">${esc(result.sector)}</div></div>
      <div><div class="detail-item-label">Employees</div><div class="detail-item-value">${result.employees}</div></div>
      <div><div class="detail-item-label">Score</div><div class="detail-item-value">${result.total_score.toFixed(1)} / ${result.max_score}</div></div>
    </div>
  `;

  if (result.management_summary) {
    html += `<div class="detail-section"><h4>Management Summary</h4><p class="section-meta">${esc(result.management_summary)}</p></div>`;
  }

  html += `<div class="detail-section"><h4>Score Breakdown</h4>`;
  const scores = result.scores || {};
  for (const [key, label] of Object.entries(dimensionLabels)) {
    const score = scores[key] || {};
    const analyzed = typeof score.score === "number" && typeof score.max_score === "number";
    const scoreText = analyzed ? `${score.score}/${score.max_score}` : "N/A";
    let status = "unknown";
    if (analyzed) {
      status = score.score === 0 ? "risk" : score.score < score.max_score ? "warning" : "ok";
    }
    html += `<div class="score-row"><span><span class="indicator indicator-${status}"></span>${label}</span><span class="score-val">${scoreText}</span></div>`;
  }
  html += `</div>`;

  if (result.key_gaps && result.key_gaps.length) {
    html += `<div class="detail-section"><h4>Key Gaps</h4>`;
    result.key_gaps.forEach((gap) => {
      html += `<div class="gap-item gap-key">${esc(gap)}</div>`;
    });
    html += `</div>`;
  }

  if ((accountSummary?.features?.conversation_starter || false) && result.sales_angles && result.sales_angles.length) {
    html += `<div class="detail-section"><h4>Conversation Starters</h4>`;
    result.sales_angles.forEach((angle) => {
      html += `<div class="sales-item">${esc(angle)}</div>`;
    });
    html += `</div>`;
  }

  if (accountSummary?.features?.lead_notes || accountSummary?.features?.follow_up_status) {
    html += `
      <div class="detail-section">
        <h4>Lead Workspace</h4>
        <label class="form-label">Follow-up status
          <select id="leadStatus" class="form-input">
            ${["new", "contacting", "qualified", "proposal", "won", "lost"]
              .map((status) => `<option value="${status}" ${status === result.follow_up_status ? "selected" : ""}>${status}</option>`)
              .join("")}
          </select>
        </label>
        <label class="form-label">Notes
          <textarea id="leadNotes" class="form-input textarea-input" rows="5">${esc(result.lead_notes || "")}</textarea>
        </label>
        <button class="btn btn-primary" onclick="saveLeadNote('${encodeURIComponent(result.domain)}')">Save Lead Workspace</button>
      </div>
    `;
  }

  if (pdfPaths[result.domain]) {
    html += `<div class="detail-section" style="text-align:center;margin-top:1rem">
      <button class="btn btn-secondary" onclick="downloadPdf('${encodeURIComponent(result.domain)}')">Download PDF Report</button>
    </div>`;
  }

  document.getElementById("detailBody").innerHTML = html;
  openModal("detailModal");
}

async function saveLeadNote(encodedDomain) {
  const domain = decodeURIComponent(encodedDomain);
  const notes = document.getElementById("leadNotes")?.value || "";
  const followUpStatus = document.getElementById("leadStatus")?.value || "new";
  try {
    await apiJson(`/api/lead-notes/${encodeURIComponent(domain)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ notes, follow_up_status: followUpStatus }),
    });
    const result = results.find((item) => item.domain === domain);
    if (result) {
      result.lead_notes = notes;
      result.follow_up_status = followUpStatus;
    }
    updateResults(results);
    alert("Lead workspace saved.");
  } catch (error) {
    alert(error.message);
  }
}

function openReport() {
  if (reportHtmlPath) window.open(reportHtmlPath, "_blank");
}

function downloadPdf(encodedDomain) {
  const domain = decodeURIComponent(encodedDomain);
  window.open(`/api/pdf/${encodeURIComponent(domain)}`, "_blank");
}

function exportJSON() {
  if (!results.length) {
    alert("No results to export.");
    return;
  }
  const blob = new Blob(
    [JSON.stringify({ generated_at: new Date().toISOString(), leads: results }, null, 2)],
    { type: "application/json" },
  );
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `lead_scout_export_${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function exportCSV() {
  if (!results.length) {
    alert("No results to export.");
    return;
  }
  const rows = [
    ["company_name", "domain", "tier", "score", "max_score", "findings_count", "sector", "follow_up_status"],
    ...results.map((result) => [
      result.company_name,
      result.domain,
      result.tier,
      result.total_score,
      result.max_score,
      result.findings_count,
      result.sector,
      result.follow_up_status || "new",
    ]),
  ];
  const csv = rows
    .map((row) => row.map((value) => `"${String(value ?? "").replaceAll('"', '""')}"`).join(","))
    .join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `lead_scout_export_${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function toggleSection(sectionId) {
  const section = document.getElementById(sectionId);
  if (!section) return;
  section.classList.toggle("collapsed");
  const icon = section.querySelector(".section-toggle-icon");
  if (icon) {
    icon.textContent = section.classList.contains("collapsed") ? "+" : "-";
  }
}

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    document.querySelectorAll(".modal-overlay.active").forEach((m) => m.classList.remove("active"));
  }
});

document.getElementById("companySearch")?.addEventListener("input", refreshCompanyTable);
document.getElementById("resultSearch")?.addEventListener("input", () => updateResults(results));
document.getElementById("resultSort")?.addEventListener("change", () => updateResults(results));

loadAccountSummary()
  .then(async () => {
    if (appMode === "account") {
      await Promise.all([loadCompanies(), loadScanHistory(), loadDomainListHistory()]);
    }
  })
  .catch((error) => {
    console.error(error);
    alert(error.message || "Failed to load the dashboard.");
  });
