let csrfToken = "";

async function apiFetch(url, options = {}) {
  const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
  if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const resp = await fetch(url, Object.assign({}, options, { headers, credentials: "same-origin" }));
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.message || "خطأ في الطلب");
  return data;
}

function showLogin() {
  document.getElementById("login-screen").classList.remove("hidden");
  document.getElementById("dashboard-screen").classList.add("hidden");
}

function showDashboard(email) {
  document.getElementById("login-screen").classList.add("hidden");
  document.getElementById("dashboard-screen").classList.remove("hidden");
  document.getElementById("admin-email-badge").textContent = email;
  loadAllData();
}

document.getElementById("admin-login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errBox = document.getElementById("login-error");
  errBox.classList.add("hidden");
  try {
    const res = await apiFetch("/api/admin/login", {
      method: "POST",
      body: JSON.stringify({
        email: document.getElementById("login-email").value,
        password_1: document.getElementById("login-pass1").value,
        password_2: document.getElementById("login-pass2").value,
      }),
    });
    csrfToken = res.csrf_token;
    document.getElementById("login-pass1").value = "";
    document.getElementById("login-pass2").value = "";
    showDashboard(res.email);
  } catch (err) {
    errBox.textContent = err.message;
    errBox.classList.remove("hidden");
  }
});

document.getElementById("logout-btn").addEventListener("click", async () => {
  await apiFetch("/api/admin/logout", { method: "POST" }).catch(() => {});
  csrfToken = "";
  showLogin();
});

document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const target = btn.dataset.tab;
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.add("hidden"));
    document.getElementById(`tab-${target}`).classList.remove("hidden");
    document.getElementById("page-title").textContent = btn.textContent;
  });
});

async function loadAllData() {
  try {
    const stats = await apiFetch("/api/admin/stats");
    renderStats(stats);
    await loadRequests();
    await loadCodes();
    await loadSettings();
    await loadVersions();
  } catch (e) {
    showLogin();
  }
}

function renderStats(s) {
  const kpis = [
    ["إجمالي الأكواد", s.total_codes],
    ["أكواد غير مستخدمة", s.unused_codes],
    ["التراخيص النشطة", s.active_licenses],
    ["طلبات تفعيل معلّقة", s.pending_requests],
    ["الأجهزة المسجلة", s.registered_devices],
    ["تنتهي خلال 15 يوم", s.expiring_soon],
    ["التراخيص المنتهية", s.expired_licenses],
    ["الأكواد الملغاة", s.revoked_codes],
  ];
  document.getElementById("kpi-grid").innerHTML = kpis
    .map(([label, val]) => `<div class="kpi-card"><span>${label}</span><strong>${val}</strong></div>`)
    .join("");

  document.getElementById("recent-activations-body").innerHTML = (s.recent_activations || [])
    .map((a) => `<tr><td>${a.code}</td><td>${a.hwid}</td><td>${a.activated_at}</td><td>${a.expires_at}</td></tr>`)
    .join("");

  const logsHtml = (s.recent_logs || [])
    .map((l) => `<tr><td>${l.action_type}</td><td>${l.target}</td><td>${l.details}</td><td>${l.created_at}</td></tr>`)
    .join("");
  document.getElementById("recent-logs-body").innerHTML = logsHtml;
  document.getElementById("full-logs-body").innerHTML = (s.recent_logs || [])
    .map((l) => `<tr><td>${l.admin_email}</td><td>${l.action_type}</td><td>${l.details}</td><td>${l.created_at}</td></tr>`)
    .join("");
}

async function loadRequests() {
  const status = document.getElementById("req-status-filter").value;
  const data = await apiFetch(`/api/admin/requests?status=${encodeURIComponent(status)}`);
  document.getElementById("requests-body").innerHTML = data.requests
    .map((r) => `
      <tr>
        <td>${r.id}</td>
        <td><strong>${r.code}</strong></td>
        <td><code>${r.hwid}</code></td>
        <td>${r.client_username}</td>
        <td>${r.requested_at}</td>
        <td><span class="badge badge-${r.status}">${r.status}</span></td>
        <td>
          ${r.status === "pending" ? `
            <button class="btn btn-primary btn-sm" onclick="reviewReq(${r.id}, 'approve')">موافقة وتفعيل</button>
            <button class="btn btn-danger btn-sm" onclick="reviewReq(${r.id}, 'reject')">رفض</button>
          ` : (r.admin_notes || "-")}
        </td>
      </tr>
    `).join("");
}

window.reviewReq = async (id, decision) => {
  let days = 365;
  if (decision === "approve") {
    const inp = prompt("أدخل مدة الاشتراك بالأيام (مثال: 365 لسنة أو 30 لشهر):", "365");
    if (!inp) return;
    days = parseInt(inp, 10) || 365;
  }
  const notes = prompt("ملاحظات إدارية (اختياري):", "") || "";
  const res = await apiFetch("/api/admin/requests/review", {
    method: "POST",
    body: JSON.stringify({ request_id: id, decision, duration_days: days, admin_notes: notes }),
  });
  alert(res.message);
  loadAllData();
};

async function loadCodes() {
  const search = document.getElementById("codes-search").value;
  const status = document.getElementById("codes-status-filter").value;
  const data = await apiFetch(`/api/admin/codes?search=${encodeURIComponent(search)}&status=${encodeURIComponent(status)}`);
  document.getElementById("codes-body").innerHTML = data.codes
    .map((c) => `
      <tr>
        <td><strong>${c.code}</strong></td>
        <td><span class="badge badge-${c.status}">${c.status}</span></td>
        <td>${c.duration_days}</td>
        <td><code>${c.hwid || "-"}</code></td>
        <td>${c.expires_at ? c.expires_at.slice(0, 10) : "-"}</td>
        <td>
          <button class="btn btn-primary btn-sm" onclick="manageCode('${c.code}', 'renew')">تجديد</button>
          <button class="btn btn-secondary btn-sm" onclick="manageCode('${c.code}', 'transfer')">نقل جهاز</button>
          <button class="btn btn-danger btn-sm" onclick="manageCode('${c.code}', 'revoke')">إلغاء</button>
        </td>
      </tr>
    `).join("");

  const activeDevs = data.codes.filter((c) => c.hwid);
  document.getElementById("devices-body").innerHTML = activeDevs
    .map((c) => `
      <tr>
        <td><strong>${c.code}</strong></td>
        <td><code>${c.hwid}</code></td>
        <td><span class="badge badge-${c.status}">${c.status}</span></td>
        <td>${c.activated_at || "-"}</td>
        <td>${c.expires_at ? c.expires_at.slice(0, 10) : "-"}</td>
        <td>
          <button class="btn btn-primary btn-sm" onclick="manageCode('${c.code}', 'renew')">تجديد</button>
          <button class="btn btn-secondary btn-sm" onclick="manageCode('${c.code}', 'transfer')">نقل لجهاز آخر</button>
          <button class="btn btn-danger btn-sm" onclick="manageCode('${c.code}', 'revoke')">إيقاف</button>
        </td>
      </tr>
    `).join("");
}

window.manageCode = async (code, action) => {
  let extra_days = 365;
  let new_hwid = "";
  if (action === "revoke" && !confirm(`هل أنت متأكد من إيقاف وإلغاء الكود ${code}؟`)) return;
  if (action === "renew") {
    const inp = prompt("أدخل عدد أيام التجديد:", "365");
    if (!inp) return;
    extra_days = parseInt(inp, 10) || 365;
  }
  if (action === "transfer") {
    new_hwid = prompt("أدخل معرف الجهاز الجديد (HWID):", "") || "";
    if (!new_hwid.trim()) return;
  }
  const res = await apiFetch("/api/admin/codes/manage", {
    method: "POST",
    body: JSON.stringify({ code, action, extra_days, new_hwid }),
  });
  alert(res.message);
  loadAllData();
};

document.getElementById("generate-batch-btn").addEventListener("click", async () => {
  const count = parseInt(document.getElementById("batch-count").value, 10) || 50;
  const duration_days = parseInt(document.getElementById("batch-days").value, 10) || 365;
  const res = await apiFetch("/api/admin/codes/generate", {
    method: "POST",
    body: JSON.stringify({ count, duration_days }),
  });
  alert(res.message);
  loadAllData();
});

document.getElementById("export-csv-btn").addEventListener("click", () => {
  window.location.href = "/api/admin/codes/export?format=csv";
});
document.getElementById("export-xlsx-btn").addEventListener("click", () => {
  window.location.href = "/api/admin/codes/export?format=xlsx";
});

document.getElementById("codes-search").addEventListener("input", loadCodes);
document.getElementById("codes-status-filter").addEventListener("change", loadCodes);
document.getElementById("req-status-filter").addEventListener("change", loadRequests);
document.getElementById("refresh-all-btn").addEventListener("click", loadAllData);

async function loadSettings() {
  const data = await apiFetch("/api/admin/settings");
  const s = data.settings || {};
  for (const k of ["app_name", "support_phone", "support_url", "grace_days", "welcome_message", "announcement", "expiry_message", "maintenance_message"]) {
    const el = document.getElementById(`rs-${k}`);
    if (el) el.value = s[k] || "";
  }
}

document.getElementById("remote-settings-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const updates = {};
  for (const k of ["app_name", "support_phone", "support_url", "grace_days", "welcome_message", "announcement", "expiry_message", "maintenance_message"]) {
    updates[k] = document.getElementById(`rs-${k}`).value;
  }
  const res = await apiFetch("/api/admin/settings", { method: "POST", body: JSON.stringify({ updates }) });
  alert(res.message);
});

async function loadVersions() {
  const data = await apiFetch("/api/admin/versions");
  document.getElementById("versions-body").innerHTML = (data.versions || [])
    .map((v) => `<tr><td><strong>${v.version}</strong></td><td>${v.release_date}</td><td>${v.description}</td><td>${v.download_url || "-"}</td></tr>`)
    .join("");
}

document.getElementById("publish-version-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const res = await apiFetch("/api/admin/versions", {
    method: "POST",
    body: JSON.stringify({
      version: document.getElementById("ver-number").value,
      download_url: document.getElementById("ver-url").value,
      description: document.getElementById("ver-desc").value,
    }),
  });
  alert(res.message);
  loadVersions();
});

document.getElementById("change-passwords-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const res = await apiFetch("/api/admin/change-passwords", {
      method: "POST",
      body: JSON.stringify({
        current_p1: document.getElementById("cp-old1").value,
        current_p2: document.getElementById("cp-old2").value,
        new_p1: document.getElementById("cp-new1").value,
        new_p2: document.getElementById("cp-new2").value,
      }),
    });
    alert(res.message);
    e.target.reset();
  } catch (err) {
    alert(err.message);
  }
});

// Check existing session on load
apiFetch("/api/admin/me")
  .then((res) => {
    csrfToken = res.csrf_token;
    showDashboard(res.email);
  })
  .catch(() => showLogin());
