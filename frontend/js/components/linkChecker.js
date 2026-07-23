// linkChecker.js — component โหมด "ตรวจลิงก์"
import { checkUrl } from "../api.js";
import { renderResult, renderLoading } from "./resultCard.js";

const EXAMPLES = [
  { label: "ลิงก์จริงของธนาคาร", url: "https://www.scb.co.th/personal-banking.html" },
  { label: "ลิงก์ปลอมเลียนแบบ", url: "http://scb-secure-login.xyz/verify?id=88421" },
  { label: "โดเมนสะกดเพี้ยน", url: "https://www.g00gle-account.com/signin" },
  { label: "ใช้เลข IP", url: "http://203.150.18.44/kbank/update.php" },
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
    renderLoading(resultEl, "กำลังตรวจสอบ — เทียบฐานข้อมูล สกมช. แล้ววิเคราะห์ลิงก์...");
    try {
      const res = await checkUrl(url);
      renderResult(resultEl, res);
    } catch (err) {
      renderResult(resultEl, { ok: false, error: err.message });
    } finally {
      button.disabled = false;
    }
  }

  button.addEventListener("click", run);
  input.addEventListener("keydown", e => { if (e.key === "Enter") run(); });
  panel.querySelectorAll(".chip").forEach(chip =>
    chip.addEventListener("click", () => { input.value = EXAMPLES[chip.dataset.i].url; run(); }));

  return { focus: () => input.focus() };
}
