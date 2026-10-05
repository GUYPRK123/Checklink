// nav.js — แถบเมนูบนสุด ใช้ร่วมกันทุกหน้า
// ทุกลิงก์บอกตรง ๆ ว่ากดแล้วไปหน้าไหน (ตรวจลิงก์ / ประวัติ / บัญชี / พรีเมียม / เข้าสู่ระบบ-ออกจากระบบ)
// และไฮไลต์หน้าที่กำลังเปิดอยู่ ไม่ให้สับสนว่าตอนนี้อยู่ตรงไหน
import { auth } from "./api.js";

const PAGE = (() => {
  const file = window.location.pathname.split("/").pop() || "index.html";
  if (file.startsWith("dashboard")) return "dashboard";
  if (file.startsWith("premium")) return "premium";
  if (file.startsWith("account")) return "account";
  return "scan";
})();
// ต้องคำนวณใหม่ทุกครั้ง ไม่ใช่ครั้งเดียวตอนโหลด: ถ้าอยู่ dashboard แล้วกด "ประวัติการตรวจ"
// (dashboard.html#history) เบราว์เซอร์แค่เลื่อนไปที่ anchor ไม่โหลดหน้าใหม่ ไฮไลต์จะค้างที่ "บัญชีของฉัน"
function currentNavKey() {
  if (PAGE === "dashboard") return window.location.hash === "#history" ? "history" : "dashboard";
  return PAGE;
}

function navLink(href, label, key) {
  return `<a class="btn ghost nav-link" href="${href}" data-nav="${key}">${label}</a>`;
}

function markCurrent(container) {
  const current = currentNavKey();
  container.querySelectorAll(".nav-link").forEach((a) => {
    const isCurrent = a.dataset.nav === current;
    a.classList.toggle("is-current", isCurrent);
    if (isCurrent) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
}

export async function mountNav(container) {
  const { user } = await auth.me().catch(() => ({ user: null }));
  window.addEventListener("hashchange", () => markCurrent(container));

  const scanLink = navLink("index.html", "ตรวจลิงก์", "scan");

  if (!user) {
    container.innerHTML = `
      ${scanLink}
      <a class="btn ghost" href="account.html">เข้าสู่ระบบ</a>
      <a class="btn" href="account.html?mode=register">สมัครฟรี</a>`;
    markCurrent(container);
    return;
  }

  const planTag = user.is_premium
    ? `<span class="nav-plan is-premium">พรีเมียม</span>`
    : `<span class="nav-plan">ฟรี</span>`;

  container.innerHTML = `
    ${scanLink}
    ${navLink("dashboard.html#history", "ประวัติการตรวจ", "history")}
    ${navLink("dashboard.html", "บัญชีของฉัน", "dashboard")}
    ${planTag}
    ${user.is_premium ? "" : navLink("premium.html", "อัพเกรดพรีเมียม", "premium")}
    <button class="btn ghost" id="nav-logout">ออกจากระบบ</button>`;
  markCurrent(container);

  container.querySelector("#nav-logout").addEventListener("click", async () => {
    await auth.logout().catch(() => {});
    window.location.reload();
  });
}
