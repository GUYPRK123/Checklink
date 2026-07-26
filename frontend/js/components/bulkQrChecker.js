// bulkQrChecker.js — สแกน QR หลายรูปพร้อมกัน (ฟีเจอร์พรีเมียม)
//
// ใช้กับกรณีที่ต้องตรวจ QR เป็นชุด เช่น รวบรวมสติกเกอร์ QR จากหลายจุดมาตรวจทีเดียว
// การถอดรหัสยังทำในเบราว์เซอร์เหมือนโหมดปกติ — ส่งขึ้นเซิร์ฟเวอร์แค่ข้อความที่ถอดได้
import { checkQrBulk } from "../api.js";
import { decodeFile } from "./qrDecode.js";
import { toneOfWarnings } from "./qrResult.js";

function esc(s) {
  return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

/** รวมคำเตือนของ QR หนึ่งอันให้เหลือสถานะเดียวสำหรับแสดงเป็นป้ายในตาราง */
const BADGE_LABEL = { red: "อันตราย", yellow: "ควรระวัง", green: "ไม่พบสิ่งผิดปกติ" };

function badgeFor(item) {
  if (item.scan?.verdict) {
    return { color: item.scan.verdict.color, label: item.scan.verdict.label };
  }
  const color = toneOfWarnings(item.qr.warnings);
  return { color, label: BADGE_LABEL[color] };
}

export function mountBulkQrChecker(panel, maxItems, onDone) {
  panel.innerHTML = `
    <div class="card">
      <label class="field-label">สแกน QR หลายรูปพร้อมกัน (สูงสุด ${maxItems} รายการต่อครั้ง)</label>
      <p class="bulk-qr-note">
        เลือกหรือลากรูป QR หลายไฟล์เข้ามาได้เลย ระบบอ่านทุกรูปในเครื่องคุณก่อน
        แล้วส่งเฉพาะเนื้อหาที่ถอดได้ไปตรวจ (รูปหนึ่งใบที่มี QR หลายอันจะถูกแยกออกให้เองด้วย)
      </p>
      <input type="file" id="bulkqr-file" accept="image/*" multiple hidden />
      <div class="qr-drop" id="bulkqr-drop">คลิกเพื่อเลือกหลายไฟล์ หรือลากรูปหลายใบมาวางที่นี่</div>
      <div class="qr-status" id="bulkqr-status"></div>
      <div id="bulkqr-result" style="margin-top:14px"></div>
    </div>`;

  const fileInput = panel.querySelector("#bulkqr-file");
  const drop = panel.querySelector("#bulkqr-drop");
  const statusEl = panel.querySelector("#bulkqr-status");
  const resultEl = panel.querySelector("#bulkqr-result");

  function setStatus(msg, tone = "") {
    statusEl.textContent = msg || "";
    statusEl.className = `qr-status${tone ? ` is-${tone}` : ""}`;
  }

  async function handleFiles(fileList) {
    const files = Array.from(fileList || []).filter(f => f.type.startsWith("image/"));
    if (!files.length) {
      setStatus("ไม่พบไฟล์รูปในรายการที่เลือก", "warn");
      return;
    }

    setStatus(`กำลังอ่าน QR จาก ${files.length} รูป...`);
    resultEl.innerHTML = "";

    const items = [];
    const emptyFiles = [];
    for (const file of files) {
      try {
        const { codes, thumb } = await decodeFile(file);
        if (!codes.length) { emptyFiles.push(file.name); continue; }
        codes.forEach((payload, i) => items.push({
          payload,
          thumb: i === 0 ? thumb : null,   // เก็บภาพย่อจากไฟล์ละครั้งเดียวพอ
          name: codes.length > 1 ? `${file.name} (QR อันที่ ${i + 1})` : file.name,
        }));
      } catch {
        emptyFiles.push(file.name);
      }
    }

    if (!items.length) {
      setStatus("อ่าน QR ไม่ได้เลยสักรูป — ลองใช้รูปที่ QR ชัดและเต็มกรอบกว่านี้", "warn");
      return;
    }
    if (items.length > maxItems) {
      setStatus(`พบ QR ${items.length} อัน เกินขีดจำกัด ${maxItems} รายการต่อครั้ง — ` +
                `ระบบจะตรวจให้เฉพาะ ${maxItems} อันแรก`, "warn");
      items.length = maxItems;
    } else {
      setStatus(`อ่าน QR ได้ ${items.length} อัน กำลังตรวจ...`);
    }

    try {
      const { results } = await checkQrBulk(items);
      renderResults(results, emptyFiles);
      if (onDone) onDone();
    } catch (err) {
      resultEl.innerHTML = `<div class="form-error">${esc(err.message)}</div>`;
      setStatus("");
    }
  }

  function renderResults(results, emptyFiles) {
    const rows = results.map(r => {
      const badge = badgeFor(r);
      const detail = r.qr.type === "url" ? r.qr.payload : `${r.qr.type_label} — ${r.qr.payload}`;
      const repeat = r.seen_before?.was_dangerous
        ? `<div class="bulkqr-repeat">เคยสแกนแล้วและครั้งนั้นพบว่าอันตราย</div>` : "";
      return `<div class="bulkqr-row">
        <div class="bulkqr-main">
          <span class="bulkqr-name">${esc(r.name)}</span>
          <span class="history-badge ${badge.color}">${esc(badge.label)}</span>
        </div>
        <code class="bulkqr-payload">${esc(detail.length > 120 ? detail.slice(0, 120) + "…" : detail)}</code>
        ${repeat}
      </div>`;
    }).join("");

    const skipped = emptyFiles.length
      ? `<div class="bulkqr-skipped">อ่าน QR ไม่ได้ ${emptyFiles.length} ไฟล์: ${esc(emptyFiles.join(", "))}</div>`
      : "";

    resultEl.innerHTML = rows + skipped;
    setStatus(`ตรวจเสร็จแล้ว ${results.length} รายการ`, "ok");
  }

  drop.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", e => {
    handleFiles(e.target.files);
    e.target.value = "";
  });
  drop.addEventListener("dragover", e => { e.preventDefault(); drop.classList.add("is-over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("is-over"));
  drop.addEventListener("drop", e => {
    e.preventDefault(); drop.classList.remove("is-over");
    handleFiles(e.dataTransfer.files);
  });
}
