// dashboard.js — หน้าบัญชีของฉัน: โควตา, ประวัติ, API key, bulk check
import { auth, billing, history } from "./api.js";
import { mountNav } from "./nav.js";
import { mountBulkChecker } from "./components/bulkChecker.js";
import { mountBulkQrChecker } from "./components/bulkQrChecker.js";

mountNav(document.getElementById("nav-actions"));

function esc(s) { return String(s).replace(/[&<>"]/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;" }[c])); }

async function init() {
  const { user } = await auth.me().catch(() => ({ user: null }));
  if (!user) {
    document.getElementById("require-login").hidden = false;
    return;
  }
  document.getElementById("dashboard-content").hidden = false;

  const status = await billing.status();
  renderPlanStatus(status);

  if (status.is_premium) {
    document.getElementById("bulk-panel").hidden = false;
    mountBulkChecker(document.getElementById("bulk-panel"), 20, refreshHistory);
    document.getElementById("bulk-qr-panel").hidden = false;
    mountBulkQrChecker(document.getElementById("bulk-qr-panel"), 20, refreshHistory);
    renderApiKeySection();
  } else {
    document.getElementById("api-key-box").innerHTML =
      `<p class="form-footer" style="text-align:left">อัพเกรดเป็น<a href="premium.html">พรีเมียม</a>เพื่อใช้งาน API key</p>`;
  }

  document.getElementById("export-link").href = history.exportUrl();
  if (!status.is_premium) {
    document.getElementById("export-link").addEventListener("click", (e) => {
      e.preventDefault();
      window.location.href = "premium.html";
    });
  }

  await refreshHistory();
}

async function refreshHistory() {
  const { history: rows } = await history.list();
  renderHistory(rows);
  if (window.location.hash === "#history") {
    document.getElementById("history").scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function renderPlanStatus(status) {
  const el = document.getElementById("plan-status");
  if (status.is_premium) {
    el.innerHTML = `<div class="a-tag ok"><span class="dot"></span>
      สมาชิกพรีเมียม — ใช้ได้ถึง ${new Date(status.premium_until).toLocaleDateString("th-TH")} (เช็คเชิงลึกไม่จำกัด)</div>`;
    return;
  }
  const pct = Math.round((status.deep_checks_remaining / status.free_daily_limit) * 100);
  el.innerHTML = `
    <div class="a-tag"><span class="dot"></span> แผนฟรี — เช็คเชิงลึกเหลือวันนี้
      <strong style="margin:0 4px">${status.deep_checks_remaining}</strong> / ${status.free_daily_limit} ครั้ง</div>
    <div class="quota-bar"><div class="quota-bar-fill" style="width:${pct}%"></div></div>
    <div class="input-row" style="margin-top:12px">
      <a class="btn" href="premium.html" style="width:100%; text-align:center">อัพเกรดเป็นพรีเมียม</a>
    </div>`;
}

// ชื่อชนิด QR ที่เก็บไว้ในประวัติ (ต้องตรงกับ analyzer/qr_payload.py ฝั่ง backend)
const QR_TYPE_LABEL = {
  url: "ลิงก์จาก QR", promptpay: "QR พร้อมเพย์", emv_unknown: "QR ชำระเงิน",
  wifi: "QR Wi-Fi", tel: "QR เบอร์โทร", sms: "QR ข้อความ SMS", email: "QR อีเมล",
  vcard: "QR นามบัตร", geo: "QR พิกัด", text: "QR ข้อความ",
};

function renderHistory(rows) {
  const el = document.getElementById("history-list");
  if (!rows.length) {
    el.innerHTML = `<p style="color:var(--muted); font-size:.88rem">ยังไม่มีประวัติการตรวจ</p>`;
    return;
  }
  el.innerHTML = rows.map(r => {
    // รายการที่มาจาก QR แสดงภาพย่อของ QR ที่สแกนไว้ด้วย (ถ้าเก็บไว้ตอนนั้น)
    const thumb = r.qr_thumb
      ? `<img class="history-thumb" src="${esc(r.qr_thumb)}" alt="ภาพ QR ที่สแกน" loading="lazy" />`
      : r.source === "qr" ? `<span class="history-thumb is-empty" aria-hidden="true">QR</span>` : "";
    const kind = r.source === "qr"
      ? `<span class="history-kind">${esc(QR_TYPE_LABEL[r.qr_type] || "จาก QR")}</span>` : "";
    return `<div class="history-row">
      ${thumb}
      <span class="history-url" title="${esc(r.url)}">${kind}${esc(r.url)}</span>
      <span class="history-badge ${r.verdict_color}">${esc(r.verdict_label)}</span>
    </div>`;
  }).join("");
}

async function renderApiKeySection() {
  const el = document.getElementById("api-key-box");
  const info = await billing.getApiKey();
  el.innerHTML = info.has_key
    ? `<p style="font-size:.88rem; color:var(--muted); margin:0 0 10px">
        มี API key อยู่แล้ว (${esc(info.key_prefix)}...) สร้างใหม่จะแทนที่ของเดิม</p>
       <button class="btn secondary" id="gen-key">สร้าง API key ใหม่</button>`
    : `<p style="font-size:.88rem; color:var(--muted); margin:0 0 10px">ยังไม่มี API key</p>
       <button class="btn secondary" id="gen-key">สร้าง API key</button>`;

  el.querySelector("#gen-key").addEventListener("click", async () => {
    try {
      const res = await billing.createApiKey();
      el.innerHTML = `<p style="font-size:.88rem; color:var(--muted); margin:0 0 6px">
          บันทึกกุญแจนี้ไว้ให้ดี ระบบจะไม่แสดงค่าเต็มอีกครั้ง:</p>
        <div class="apikey-box">${esc(res.api_key)}</div>
        <p style="font-size:.8rem; color:var(--muted); margin-top:8px">
          ใช้งานโดยแนบ header <code>X-API-Key</code> ตอนเรียก <code>/api/check</code></p>`;
    } catch (err) {
      el.innerHTML = `<div class="form-error">${esc(err.message)}</div>`;
    }
  });
}

init();
