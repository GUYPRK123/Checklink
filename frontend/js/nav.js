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
const ON_HISTORY_SECTION = PAGE === "dashboard" && window.location.hash === "#history";

function navLink(href, label, isCurrent) {
  return `<a class="btn ghost nav-link${isCurrent ? " is-current" : ""}" href="${href}"${isCurrent ? ' aria-current="page"' : ""}>${label}</a>`;
}

export async function mountNav(container) {
  const { user } = await auth.me().catch(() => ({ user: null }));

  const scanLink = navLink("index.html", "ตรวจลิงก์", PAGE === "scan");

  if (!user) {
    container.innerHTML = `
      ${scanLink}
      <a class="btn ghost" href="account.html">เข้าสู่ระบบ</a>
      <a class="btn" href="account.html?mode=register">สมัครฟรี</a>`;
    return;
  }

  const planTag = user.is_premium
    ? `<span class="nav-plan is-premium">พรีเมียม</span>`
    : `<span class="nav-plan">ฟรี</span>`;

  container.innerHTML = `
    ${scanLink}
    ${navLink("dashboard.html#history", "ประวัติการตรวจ", ON_HISTORY_SECTION)}
    ${navLink("dashboard.html", "บัญชีของฉัน", PAGE === "dashboard" && !ON_HISTORY_SECTION)}
    ${planTag}
    ${user.is_premium ? "" : navLink("premium.html", "อัพเกรดพรีเมียม", PAGE === "premium")}
    <button class="btn ghost" id="nav-logout">ออกจากระบบ</button>`;

  container.querySelector("#nav-logout").addEventListener("click", async () => {
    await auth.logout().catch(() => {});
    window.location.reload();
  });
}
