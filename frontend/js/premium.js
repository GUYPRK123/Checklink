// premium.js — หน้าเทียบแผน + จำลองการชำระเงิน
import { auth, billing } from "./api.js";
import { mountNav } from "./nav.js";

mountNav(document.getElementById("nav-actions"));

const plansEl = document.getElementById("plans");
const checkoutSection = document.getElementById("checkout-section");
const checkoutMsg = document.getElementById("checkout-msg");

function esc(s) { return String(s).replace(/[&<>"]/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;" }[c])); }

async function init() {
  const { user } = await auth.me().catch(() => ({ user: null }));
  const { plans } = await billing.plans();

  plansEl.innerHTML = plans.map(p => `
    <div class="plan-card ${p.id === "premium" ? "is-premium" : ""}">
      <div class="plan-name">${esc(p.name)}</div>
      <div class="plan-price">${p.price_thb === 0 ? "ฟรี" : `฿${p.price_thb}`}${p.duration_days ? `<small> / ${p.duration_days} วัน</small>` : ""}</div>
      <ul class="plan-features">${p.features.map(f => `<li>${esc(f)}</li>`).join("")}</ul>
    </div>`).join("");

  if (!user) {
    checkoutSection.hidden = true;
    plansEl.insertAdjacentHTML("afterend",
      `<p class="form-footer" style="margin-top:18px">
        <a href="account.html?mode=register">สมัครสมาชิกฟรี</a> ก่อน แล้วค่อยกลับมาอัพเกรดพรีเมียมได้เลย
      </p>`);
    return;
  }

  if (user.is_premium) {
    checkoutSection.hidden = true;
    plansEl.insertAdjacentHTML("afterend",
      `<div class="form-success" style="margin-top:18px">
        คุณเป็นสมาชิกพรีเมียมอยู่แล้ว (ใช้ได้ถึง ${new Date(user.premium_until).toLocaleDateString("th-TH")})
      </div>`);
    return;
  }

  checkoutSection.hidden = false;
}

init();

// ---- สลับวิธีชำระเงิน ----
const tabCard = document.getElementById("tab-card");
const tabPromptpay = document.getElementById("tab-promptpay");
const cardForm = document.getElementById("card-form");
const promptpayForm = document.getElementById("promptpay-form");

tabCard.addEventListener("click", () => {
  tabCard.classList.add("is-active"); tabPromptpay.classList.remove("is-active");
  cardForm.hidden = false; promptpayForm.hidden = true;
});
tabPromptpay.addEventListener("click", () => {
  tabPromptpay.classList.add("is-active"); tabCard.classList.remove("is-active");
  promptpayForm.hidden = false; cardForm.hidden = true;
});

function showResult(html, ok) {
  checkoutMsg.innerHTML = `<div class="${ok ? "form-success" : "form-error"}">${html}</div>`;
}

cardForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  checkoutMsg.innerHTML = "";
  try {
    const res = await billing.checkout({
      method: "card",
      card_number: document.getElementById("card-number").value.replace(/\s+/g, ""),
      expiry: document.getElementById("card-expiry").value.trim(),
      cvc: document.getElementById("card-cvc").value.trim(),
    });
    showResult(`${esc(res.demo_notice)} (เลขอ้างอิง: ${esc(res.txn_id)}) กำลังพาไปหน้าบัญชี...`, true);
    setTimeout(() => window.location.href = "dashboard.html", 1500);
  } catch (err) {
    showResult(esc(err.message), false);
  }
});

promptpayForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  checkoutMsg.innerHTML = "";
  try {
    const res = await billing.checkout({
      method: "promptpay",
      promptpay_ref: document.getElementById("pp-ref").value.trim(),
    });
    showResult(`${esc(res.demo_notice)} (เลขอ้างอิง: ${esc(res.txn_id)}) กำลังพาไปหน้าบัญชี...`, true);
    setTimeout(() => window.location.href = "dashboard.html", 1500);
  } catch (err) {
    showResult(esc(err.message), false);
  }
});
