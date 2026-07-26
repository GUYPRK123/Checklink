// qrResult.js — การ์ดอธิบาย "เนื้อหาที่อยู่ใน QR" (ใช้คู่กับ resultCard.js)
//
// resultCard.js ตอบคำถามว่า "ลิงก์นี้อันตรายไหม"
// ไฟล์นี้ตอบคำถามที่มาก่อนหน้านั้นว่า "QR อันนี้มันคืออะไร และกดแล้วจะเกิดอะไรขึ้น"
// ซึ่งสำคัญมากกับ QR ที่ไม่ใช่ลิงก์ (พร้อมเพย์ / Wi-Fi / เบอร์โทร) ที่เดิมระบบตอบแค่
// "ตรวจไม่ได้" แล้วจบ

const SEV_ICON = { critical: "!", high: "!", medium: "?", low: "·" };

function esc(s) {
  return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

/** สีของกรอบการ์ด: เฉพาะ critical เท่านั้นที่เป็นแดง (ต้องตรงกับ _warnings_color ใน check.py)
 *  เหตุผลที่ high ไม่เป็นแดง: สติกเกอร์พร้อมเพย์ของร้านค้าที่ถูกต้องก็เข้าเงื่อนไข high
 *  ถ้าตีเป็นแดงหมด ผู้ใช้จะชินกับสีแดงแล้วเลิกอ่านคำเตือน */
export function toneOfWarnings(warnings) {
  const levels = new Set((warnings || []).map(w => w.severity));
  if (levels.has("critical")) return "red";
  if (levels.has("high") || levels.has("medium")) return "yellow";
  return "green";
}

function factsHTML(items, title) {
  if (!items || !items.length) return "";
  const rows = items.map(f => `
    <div class="a-tag ${f.state || ""}"><span class="dot"></span>
      <span><strong>${esc(f.label)}:</strong> ${esc(f.value)}</span>
    </div>`).join("");
  return `<div class="anatomy"><div class="a-label">${esc(title)}</div>${rows}</div>`;
}

function warningsHTML(warnings) {
  if (!warnings || !warnings.length) return "";
  const items = warnings.map(w => `
    <div class="reason sev-${w.severity}">
      <span class="r-ico">${SEV_ICON[w.severity] || "·"}</span>
      <span><span class="r-title">${esc(w.title)}</span><span class="r-detail">${esc(w.detail)}</span></span>
    </div>`).join("");
  return `<div class="reasons"><h3>สิ่งที่ควรระวังกับ QR แบบนี้</h3>${items}</div>`;
}

function lockedHTML(qr) {
  if (!qr.details_locked) return "";
  return `<div class="upsell">
    <p>${esc(qr.details_locked_message)}</p>
    <a class="btn secondary" href="premium.html">อัพเกรดพรีเมียม</a>
  </div>`;
}

function seenBeforeHTML(seen) {
  if (!seen) return "";
  const when = new Date(seen.last_seen).toLocaleString("th-TH");
  if (seen.was_dangerous) {
    return `<div class="qr-repeat is-danger">
      <strong>คุณเคยสแกนสิ่งนี้มาแล้ว และครั้งนั้นระบบตัดสินว่าอันตราย</strong>
      <span>เคยสแกนทั้งหมด ${seen.count} ครั้ง ล่าสุดเมื่อ ${esc(when)}</span>
    </div>`;
  }
  return `<div class="qr-repeat">
    <strong>คุณเคยสแกนสิ่งนี้มาแล้ว ${seen.count} ครั้ง</strong>
    <span>ล่าสุดเมื่อ ${esc(when)} — ผลครั้งนั้นคือ “${esc(seen.last_verdict_label)}”</span>
  </div>`;
}

/** ปุ่มจัดการเนื้อหาใน QR: คัดลอกได้เสมอ ส่วนปุ่มเปิดจะมีเฉพาะ QR ที่เป็นลิงก์ */
function actionsHTML(qr, scan) {
  const canOpen = qr.type === "url";
  const openTone = scan?.verdict?.color === "green" ? "" : " is-risky";
  return `<div class="qr-actions">
    <button class="btn secondary" data-qr-copy>คัดลอกเนื้อหาใน QR</button>
    ${canOpen ? `<button class="btn secondary${openTone}" data-qr-open>เปิดลิงก์นี้ในแท็บใหม่</button>` : ""}
  </div>`;
}

/**
 * วาดการ์ด QR ลงใน container
 * @param {HTMLElement} container
 * @param {object} data ผลจาก /api/check/qr — { qr, scan, seen_before }
 * @returns {void}
 */
export function renderQrInfo(container, data) {
  const qr = data.qr;
  const tone = qr.type === "url" ? "" : toneOfWarnings(qr.warnings);

  container.innerHTML = `
    <div class="qr-card${tone ? ` tone-${tone}` : ""}">
      <div class="qr-card-head">
        <span class="qr-kind">${esc(qr.type_label)}</span>
        <span class="qr-action-note">สแกนด้วยแอปทั่วไปแล้วจะ: ${esc(qr.action)}</span>
      </div>
      <div class="qr-payload-box">
        <div class="qr-payload-label">เนื้อหาที่อยู่ใน QR จริง ๆ</div>
        <code class="qr-payload">${esc(qr.payload)}</code>
      </div>
      ${actionsHTML(qr, data.scan)}
      ${seenBeforeHTML(data.seen_before)}
      ${factsHTML(qr.facts, "ข้อมูลที่อ่านได้จาก QR")}
      ${factsHTML(qr.details, "รายละเอียดเต็ม (สมาชิกพรีเมียม)")}
      ${lockedHTML(qr)}
      ${warningsHTML(qr.warnings)}
    </div>`;

  const copyBtn = container.querySelector("[data-qr-copy]");
  copyBtn?.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(qr.payload);
      copyBtn.textContent = "คัดลอกแล้ว";
    } catch {
      copyBtn.textContent = "คัดลอกไม่ได้ ให้ลากคลุมข้อความแล้วก๊อปเอง";
    }
    setTimeout(() => { copyBtn.textContent = "คัดลอกเนื้อหาใน QR"; }, 2000);
  });

  // ปุ่มเปิดลิงก์: ถ้าผลตรวจไม่ใช่ "ปลอดภัย" ต้องยืนยันอีกชั้นก่อนเปิดจริง
  const openBtn = container.querySelector("[data-qr-open]");
  openBtn?.addEventListener("click", () => {
    const color = data.scan?.verdict?.color;
    if (color !== "green" && !openBtn.dataset.confirming) {
      openBtn.dataset.confirming = "1";
      openBtn.textContent = color === "red"
        ? "ระบบตัดสินว่าอันตราย — กดอีกครั้งถ้ายืนยันจะเปิด"
        : "ยังยืนยันความปลอดภัยไม่ได้ — กดอีกครั้งถ้ายืนยันจะเปิด";
      return;
    }
    const url = /^https?:\/\//i.test(qr.payload) ? qr.payload : `http://${qr.payload}`;
    window.open(url, "_blank", "noopener,noreferrer");
  });
}
