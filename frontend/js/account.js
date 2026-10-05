// account.js — หน้าเข้าสู่ระบบ/สมัครสมาชิก
import { auth } from "./api.js";
import { mountNav } from "./nav.js";

mountNav(document.getElementById("nav-actions"));

const tabLogin = document.getElementById("tab-login");
const tabRegister = document.getElementById("tab-register");
const loginForm = document.getElementById("login-form");
const registerForm = document.getElementById("register-form");
const msgEl = document.getElementById("form-msg");

function activate(mode) {
  const isLogin = mode === "login";
  tabLogin.classList.toggle("is-active", isLogin);
  tabRegister.classList.toggle("is-active", !isLogin);
  tabLogin.setAttribute("aria-selected", String(isLogin));
  tabRegister.setAttribute("aria-selected", String(!isLogin));
  loginForm.hidden = !isLogin;
  registerForm.hidden = isLogin;
  msgEl.innerHTML = "";
}

tabLogin.addEventListener("click", () => activate("login"));
tabRegister.addEventListener("click", () => activate("register"));

const params = new URLSearchParams(window.location.search);
activate(params.get("mode") === "register" ? "register" : "login");

function showError(text) {
  msgEl.innerHTML = `<div class="form-error">${text}</div>`;
}

loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  msgEl.innerHTML = "";
  try {
    await auth.login(
      document.getElementById("login-email").value.trim(),
      document.getElementById("login-password").value);
    window.location.href = "dashboard.html";
  } catch (err) {
    showError(err.message);
  }
});

registerForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  msgEl.innerHTML = "";
  const email = document.getElementById("reg-email").value.trim();
  const password = document.getElementById("reg-password").value;
  let res;
  try {
    res = await auth.register(email, password);
  } catch (err) {
    showError(err.message);
    return;
  }
  // backend ไม่ auto-login หลังสมัครแล้ว (กัน email enumeration ดู auth.py) ถ้าพาไป
  // dashboard ตรง ๆ ผู้ใช้จะเจอหน้า "กรุณาเข้าสู่ระบบ" ทันทีหลังสมัครเสร็จ จึงล็อกอินต่อให้เอง
  // ถ้าล็อกอินไม่ผ่าน (อีเมลมีอยู่แล้วแต่รหัสไม่ตรง) ให้ไปแท็บเข้าสู่ระบบพร้อมข้อความกลาง ๆ จาก backend
  try {
    await auth.login(email, password);
    window.location.href = "dashboard.html";
  } catch {
    activate("login");
    document.getElementById("login-email").value = email;
    msgEl.innerHTML = `<div class="form-success">${res.message}</div>`;
  }
});
