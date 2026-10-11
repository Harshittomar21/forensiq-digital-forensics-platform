const state = {
  dashboard: null,
  showAllEvidence: false,
  showAllEvents: false,
  query: "",
};

const $ = (selector) => document.querySelector(selector);
const elements = {
  activeCaseId: $("#activeCaseId"),
  activeCaseTitle: $("#activeCaseTitle"),
  caseSelect: $("#caseSelect"),
  caseMenu: $("#caseMenu"),
  breadcrumbCase: $("#breadcrumbCase"),
  caseTitle: $("#caseTitle"),
  casePriority: $("#casePriority"),
  caseStatus: $("#caseStatus"),
  caseSummary: $("#caseSummary"),
  riskScore: $("#riskScore"),
  integrityScore: $("#integrityScore"),
  integrityCaption: $("#integrityCaption"),
  evidenceNavCount: $("#evidenceNavCount"),
  evidenceTitleCount: $("#evidenceTitleCount"),
  ringCount: $("#ringCount"),
  vaultIntegrity: $("#vaultIntegrity"),
  verifiedCount: $("#verifiedCount"),
  queuedCount: $("#queuedCount"),
  notificationCount: $("#notificationCount"),
  scanMessage: $("#scanMessage"),
  lastScan: $("#lastScan"),
  timelineList: $("#timelineList"),
  evidenceRows: $("#evidenceRows"),
  tableMessage: $("#tableMessage"),
  searchInput: $("#searchInput"),
  acquireDialog: $("#acquireDialog"),
  acquireForm: $("#acquireForm"),
  detailDrawer: $("#detailDrawer"),
  drawerContent: $("#drawerContent"),
  toast: $("#toast"),
  runAnalysisBtn: $("#runAnalysisBtn"),
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[char]));
}

function iconFor(kind) {
  const common = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 3h7l4 4v14H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z"/>';
  if (kind === "Disk image") return '<svg viewBox="0 0 24 24" aria-hidden="true"><ellipse cx="12" cy="6" rx="6.5" ry="2.5"/><path d="M5.5 6v6c0 1.4 2.9 2.5 6.5 2.5s6.5-1.1 6.5-2.5V6M5.5 12v6c0 1.4 2.9 2.5 6.5 2.5s6.5-1.1 6.5-2.5v-6"/></svg>';
  if (kind === "Network capture") return '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="6" cy="7" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="17" cy="18" r="2"/><path d="m7.8 7 8.2-.7M7.4 8.5l8 8"/></svg>';
  if (kind === "Memory image") return '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="6" y="6" width="12" height="12" rx="1"/><path d="M9 3v3m3-3v3m3-3v3M9 18v3m3-3v3m3-3v3M3 9h3m-3 3h3m-3 3h3m12-6h3m-3 3h3m-3 3h3"/></svg>';
  return `${common}<path d="M14 3v5h5M9 13h6M9 17h4"/></svg>`;
}

async function request(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "The request could not be completed.");
  return data;
}

function renderCase(data) {
  const c = data.case;
  elements.activeCaseId.textContent = c.id;
  elements.activeCaseTitle.textContent = c.title;
  elements.breadcrumbCase.textContent = c.id;
  elements.caseTitle.textContent = c.title;
  elements.caseSummary.textContent = c.summary;
  elements.casePriority.innerHTML = `<i></i>${escapeHtml(c.priority)}`;
  elements.caseStatus.textContent = c.status;
  elements.caseStatus.className = "status-chip purple";
  elements.evidenceNavCount.textContent = c.evidence_count;
  elements.evidenceTitleCount.textContent = `(${c.evidence_count})`;
  elements.ringCount.textContent = c.evidence_count;
  elements.vaultIntegrity.textContent = `${data.metrics.integrity}%`;
}

function renderMetrics(data) {
  elements.riskScore.textContent = data.metrics.risk_score;
  elements.integrityScore.textContent = `${data.metrics.integrity}%`;
  elements.integrityCaption.textContent = `${data.case.evidence_count} of ${data.case.evidence_count} artifacts hashed`;
  const verified = data.evidence.filter((item) => item.status === "Verified").length;
  const queued = data.evidence.filter((item) => item.status === "Queued").length;
  elements.verifiedCount.textContent = verified;
  elements.queuedCount.textContent = queued;
  elements.notificationCount.textContent = data.notifications;
  elements.scanMessage.textContent = data.scan_message;
  elements.lastScan.textContent = data.last_scan;
}

function renderCaseMenu(data) {
  elements.caseMenu.innerHTML = data.cases.map((item) => `
    <button type="button" data-case="${escapeHtml(item.id)}">
      <b>${escapeHtml(item.id)}</b><span>${escapeHtml(item.title)} · ${escapeHtml(item.status)}</span>
    </button>`).join("");
}

function renderTimeline(data) {
  const timeline = state.showAllEvents ? data.timeline : data.timeline.slice(0, 5);
  elements.timelineList.innerHTML = timeline.map((item) => `
    <article class="timeline-item">
      <time class="timeline-time">${escapeHtml(item.time)}</time>
      <span class="timeline-rail"><i class="timeline-dot ${escapeHtml(item.kind)}"></i></span>
      <div class="timeline-content"><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.detail)}</p></div>
    </article>`).join("");
  $("#showAllEvents").innerHTML = state.showAllEvents ? 'Collapse timeline <span>↑</span>' : 'Show full timeline <span>↓</span>';
}

function filteredEvidence(data) {
  const query = state.query.trim().toLowerCase();
  if (!query) return data.evidence;
  return data.evidence.filter((item) => [item.id, item.name, item.kind, item.source, item.hash, ...item.tags].join(" ").toLowerCase().includes(query));
}

function renderEvidence(data) {
  const filtered = filteredEvidence(data);
  const visible = state.showAllEvidence || state.query ? filtered : filtered.slice(0, 5);
  elements.evidenceRows.innerHTML = visible.length ? visible.map((item) => {
    const tags = item.tags.slice(0, 2).map((tag) => `<span class="tag">${escapeHtml(tag)}</span>`).join("");
    const integrityClass = item.status === "Queued" ? "queued" : "";
    return `<tr data-evidence="${escapeHtml(item.id)}">
      <td><div class="artifact-name"><span class="file-icon">${iconFor(item.kind)}</span><div><b>${escapeHtml(item.name)}</b><span>${escapeHtml(item.id)} · ${escapeHtml(item.kind)}</span></div></div></td>
      <td>${escapeHtml(item.source)}${tags}</td><td class="mono">${escapeHtml(item.collected)}</td>
      <td class="mono">${escapeHtml(item.hash)}</td><td><span class="integrity-tag ${integrityClass}">${escapeHtml(item.status)}</span></td>
      <td><button type="button" class="row-menu" aria-label="View ${escapeHtml(item.name)}">•••</button></td></tr>`;
  }).join("") : '<tr><td colspan="6" class="no-results">No artifacts match this search.</td></tr>';
  const total = data.case.evidence_count;
  elements.tableMessage.textContent = state.query
    ? `${filtered.length} matching artifact${filtered.length === 1 ? "" : "s"}`
    : `Showing ${visible.length} of ${total} registered artifacts`;
  $("#showAllEvidence").innerHTML = state.showAllEvidence ? 'Show sampled register <span>↑</span>' : 'Open evidence vault <span>→</span>';
}

function render(data) {
  state.dashboard = data;
  renderCase(data);
  renderMetrics(data);
  renderCaseMenu(data);
  renderTimeline(data);
  renderEvidence(data);
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add("show");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => elements.toast.classList.remove("show"), 3100);
}

function openDetail(id) {
  const item = state.dashboard?.evidence.find((evidence) => evidence.id === id);
  if (!item) return;
  elements.drawerContent.innerHTML = `
    <div class="drawer-field"><span>Artifact</span><b>${escapeHtml(item.name)}</b></div>
    <div class="drawer-field"><span>Evidence reference</span><b class="mono">${escapeHtml(item.id)}</b></div>
    <div class="drawer-field"><span>Origin</span><b>${escapeHtml(item.source)}</b></div>
    <div class="drawer-field"><span>Fingerprint</span><b class="mono">${escapeHtml(item.algorithm)} · ${escapeHtml(item.hash)}</b></div>
    <div class="drawer-field"><span>Custodian</span><b>${escapeHtml(item.custodian)}</b></div>
    <div class="drawer-field"><span>Examiner note</span><p>${escapeHtml(item.note)}</p></div>`;
  elements.detailDrawer.classList.add("open");
  elements.detailDrawer.setAttribute("aria-hidden", "false");
}

async function loadDashboard() {
  try {
    const data = await request("/api/dashboard");
    render(data);
  } catch (error) {
    showToast(error.message);
  }
}

elements.caseSelect.addEventListener("click", () => {
  const nowOpen = elements.caseMenu.hidden;
  elements.caseMenu.hidden = !nowOpen;
  elements.caseSelect.setAttribute("aria-expanded", String(nowOpen));
});

elements.caseMenu.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-case]");
  if (!button) return;
  elements.caseMenu.hidden = true;
  elements.caseSelect.setAttribute("aria-expanded", "false");
  if (button.dataset.case !== "CASE-2026-042") {
    showToast("The complete evidence workspace is provisioned for CASE-2026-042 in this prototype.");
  }
});

document.addEventListener("click", (event) => {
  if (!$("#casePicker").contains(event.target)) {
    elements.caseMenu.hidden = true;
    elements.caseSelect.setAttribute("aria-expanded", "false");
  }
});

elements.searchInput.addEventListener("input", (event) => {
  state.query = event.target.value;
  state.showAllEvidence = Boolean(state.query);
  if (state.dashboard) renderEvidence(state.dashboard);
});

document.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    elements.searchInput.focus();
  }
  if (event.key === "Escape") {
    elements.detailDrawer.classList.remove("open");
    elements.detailDrawer.setAttribute("aria-hidden", "true");
  }
});

$("#showAllEvidence").addEventListener("click", () => {
  state.showAllEvidence = !state.showAllEvidence;
  renderEvidence(state.dashboard);
});

$("#showAllEvents").addEventListener("click", () => {
  state.showAllEvents = !state.showAllEvents;
  renderTimeline(state.dashboard);
});

elements.evidenceRows.addEventListener("click", (event) => {
  const row = event.target.closest("tr[data-evidence]");
  if (row) openDetail(row.dataset.evidence);
});

$("#addEvidenceBtn").addEventListener("click", () => elements.acquireDialog.showModal());
$("#closeDialog").addEventListener("click", () => elements.acquireDialog.close());
$("#cancelDialog").addEventListener("click", () => elements.acquireDialog.close());

elements.acquireForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(elements.acquireForm);
  const submit = elements.acquireForm.querySelector('[type="submit"]');
  submit.textContent = "Registering…";
  submit.disabled = true;
  try {
    const data = await request("/api/evidence/acquire", { method: "POST", body: JSON.stringify(Object.fromEntries(form)) });
    elements.acquireDialog.close();
    elements.acquireForm.reset();
    state.showAllEvidence = true;
    render(data);
    showToast("Artifact registered and added to the custody ledger.");
  } catch (error) {
    showToast(error.message);
  } finally {
    submit.textContent = "Register artifact";
    submit.disabled = false;
  }
});

elements.runAnalysisBtn.addEventListener("click", async () => {
  const original = elements.runAnalysisBtn.innerHTML;
  elements.runAnalysisBtn.innerHTML = "<span>Analyzing…</span>";
  elements.runAnalysisBtn.disabled = true;
  try {
    const data = await request("/api/analysis/run", { method: "POST", body: "{}" });
    render(data);
    showToast("Correlation pass complete. A new review path was added.");
  } catch (error) {
    showToast(error.message);
  } finally {
    elements.runAnalysisBtn.innerHTML = original;
    elements.runAnalysisBtn.disabled = false;
  }
});

function downloadReport() {
  window.location.assign("/api/report");
}

$("#exportBtn").addEventListener("click", downloadReport);
$("#reportBtn").addEventListener("click", downloadReport);
$("#focusTimeline").addEventListener("click", () => $("#timeline").scrollIntoView({ behavior: "smooth", block: "start" }));
$("#inspectCorrelation").addEventListener("click", () => $("#graph").scrollIntoView({ behavior: "smooth", block: "center" }));
$("#viewCustodyBtn").addEventListener("click", () => { showToast("The custody ledger is visible in the investigation brief export."); });
$("#expandGraph").addEventListener("click", () => { showToast("Graph expansion is represented by the connected entity view in this prototype."); });
$("#evidenceFilterBtn").addEventListener("click", () => { showToast("Use the global search to filter the artifact register."); });
$("#notifyBtn").addEventListener("click", () => { showToast(`${state.dashboard?.notifications ?? 0} review notifications are awaiting the lead examiner.`); });
$("#closeDrawer").addEventListener("click", () => { elements.detailDrawer.classList.remove("open"); elements.detailDrawer.setAttribute("aria-hidden", "true"); });

function updateClock() {
  const now = new Date();
  $("#utcClock").textContent = `UTC ${now.toISOString().slice(11, 19)}`;
}

updateClock();
window.setInterval(updateClock, 1000);
loadDashboard();
