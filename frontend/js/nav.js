// nav.js — เติมปุ่มเข้าสู่ระบบ/บัญชีของฉันในส่วนหัว ใช้ร่วมกันทุกหน้า
import { auth } from "./api.js";

export async function mountNav(container) {
  const { user } = await auth.me().catch(() => ({ user: null }));

  if (!user) {
    container.innerHTML = `
      <a class="btn ghost" href="account.html">เข้าสู่ระบบ</a>
      <a class="btn" href="account.html?mode=register">สมัครฟรี</a>`;
    return;
  }

  const planTag = user.is_premium
    ? `<span class="nav-plan is-premium">พรีเมียม</span>`
    : `<span class="nav-plan">ฟรี</span>`;

  container.innerHTML = `
    ${planTag}
    <a class="btn ghost" href="dashboard.html">บัญชีของฉัน</a>
    ${user.is_premium ? "" : `<a class="btn" href="premium.html">อัพเกรด</a>`}
    <button class="btn ghost" id="nav-logout">ออกจากระบบ</button>`;

  container.querySelector("#nav-logout").addEventListener("click", async () => {
    await auth.logout().catch(() => {});
    window.location.reload();
  });
}
