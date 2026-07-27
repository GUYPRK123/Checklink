// bulkChecker.js — component เช็คลิงก์หลายรายการพร้อมกัน (ฟีเจอร์พรีเมียม)
import { checkUrlsBulk } from "../api.js";

function esc(s) { return String(s).replace(/[&<>"]/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;" }[c])); }

export function mountBulkChecker(panel, maxUrls, onDone) {
  panel.innerHTML = `
    <div class="card">
      <label class="field-label" for="bulk-input">เช็คหลายลิงก์พร้อมกัน (บรรทัดละ 1 ลิงก์ สูงสุด ${maxUrls} ลิงก์)</label>
      <textarea id="bulk-input" class="bulk-input" placeholder="https://example.com\nhttps://another-site.com"></textarea>
      <div class="input-row" style="margin-top:12px">
        <button class="btn" id="bulk-go" style="width:100%">เช็คทั้งหมด</button>
      </div>
      <div id="bulk-result" style="margin-top:14px"></div>
    </div>`;

  const input = panel.querySelector("#bulk-input");
  const button = panel.querySelector("#bulk-go");
  const resultEl = panel.querySelector("#bulk-result");

  button.addEventListener("click", async () => {
    const urls = input.value.split("\n").map(s => s.trim()).filter(Boolean);
    if (!urls.length) return;
    button.disabled = true;
    // งานทำเบื้องหลังแล้วรายงานความคืบหน้ากลับมา จึงบอกผู้ใช้ได้ว่าถึงไหนแล้ว
    // แทนที่จะให้หมุนเฉย ๆ โดยไม่รู้ว่าค้างหรือยังทำอยู่
    const showProgress = (done, total) => {
      resultEl.innerHTML = `<div class="loading"><span class="spin"></span> ` +
        `กำลังเช็ค ${esc(String(done))}/${esc(String(total))} ลิงก์...</div>`;
    };
    showProgress(0, urls.length);
    try {
      const { results } = await checkUrlsBulk(urls, showProgress);
      resultEl.innerHTML = results.map(r => {
        if (!r.ok) return `<div class="history-row"><span class="history-url">${esc(r.input || "")}</span>
          <span class="history-badge yellow">ตรวจไม่ได้</span></div>`;
        return `<div class="history-row"><span class="history-url">${esc(r.input)}</span>
          <span class="history-badge ${r.verdict.color}">${esc(r.verdict.label)}</span></div>`;
      }).join("");
      if (onDone) onDone();
    } catch (err) {
      resultEl.innerHTML = `<div class="form-error">${esc(err.message)}</div>`;
    } finally {
      button.disabled = false;
    }
  });
}
