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
  try {
    await auth.register(
      document.getElementById("reg-email").value.trim(),
      document.getElementById("reg-password").value);
    window.location.href = "dashboard.html";
  } catch (err) {
    showError(err.message);
  }
});
