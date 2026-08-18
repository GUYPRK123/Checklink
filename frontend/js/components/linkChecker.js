// linkChecker.js — component โหมด "ตรวจลิงก์"
import { checkUrl } from "../api.js";
import { renderResult, renderScanProgress } from "./resultCard.js";

// ตัวอย่างครอบคลุมกลไกตรวจจับหลักของระบบคนละแบบ — ทุกลิงก์อันตรายเป็นลิงก์สมมติ
// ที่แต่งขึ้นให้เข้ารูปแบบที่ระบบจับได้ ไม่ใช่เว็บอันตรายจริง (ยกเว้นลิงก์ธนาคารจริง)
// สี่ตัวอย่างท้ายถูกตัดสินได้จากชั้น 1-2 แบบออฟไลน์ จึงไม่เปลืองโควตาตรวจเชิงลึก
const EXAMPLES = [
  { label: "ลิงก์จริงของธนาคาร", url: "https://www.scb.co.th/personal-banking.html" },
  { label: "ลิงก์ปลอมเลียนแบบ", url: "http://scb-secure-login.xyz/verify?id=88421" },
  { label: "โดเมนสะกดเพี้ยน", url: "https://www.g00gle-account.com/signin" },
  { label: "ใช้เลข IP", url: "http://203.150.18.44/kbank/update.php" },
  { label: "อักษรเลียนแบบสายตา", url: "https://ѕcb.co.th/promo" },
  { label: "ลิงก์ javascript: ฝังโค้ด", url: "javascript:document.location='http://attacker.example'" },
  { label: "สคริปต์แฝงในพารามิเตอร์", url: "http://lucky-prize.top/claim?msg=<script>alert(1)</script>" },
  { label: "หลอกโหลดแอป .apk", url: "http://krungthai-verify.top/app/KTB-NextGen.apk" },
];

export function mountLinkChecker(panel, resultEl) {
  panel.innerHTML = `
    <div class="card">
      <label class="field-label" for="url-input">วางลิงก์ที่ต้องการตรวจ</label>
      <div class="input-row">
        <input id="url-input" type="text" inputmode="url" autocomplete="off" spellcheck="false"
               placeholder="เช่น https://scb.co.th หรือ paypal-login.xyz" />
        <button class="btn" id="url-go">ตรวจลิงก์</button>
      </div>
      <div class="examples">
        <span>ลองตัวอย่าง:</span>
        ${EXAMPLES.map((e, i) => `<span class="chip" data-i="${i}">${e.label}</span>`).join("")}
      </div>
    </div>`;

  const input = panel.querySelector("#url-input");
  const button = panel.querySelector("#url-go");

  async function run() {
    const url = input.value.trim();
    if (!url) { input.focus(); return; }
    button.disabled = true;
    const progress = renderScanProgress(resultEl);  // โชว์ขั้น 4 ชั้นระหว่างรอ
    try {
      const res = await checkUrl(url);
      renderResult(resultEl, res);
    } catch (err) {
      renderResult(resultEl, { ok: false, error: err.message });
    } finally {
      progress.stop();          // ผลมาแล้ว (DOM ถูกแทนที่) — เก็บกวาด timer ที่เหลือ
      button.disabled = false;
    }
  }

  button.addEventListener("click", run);
  input.addEventListener("keydown", e => { if (e.key === "Enter") run(); });
  panel.querySelectorAll(".chip").forEach(chip =>
    chip.addEventListener("click", () => { input.value = EXAMPLES[chip.dataset.i].url; run(); }));

  return { focus: () => input.focus() };
}
