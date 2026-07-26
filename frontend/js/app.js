// app.js — จุดเริ่มต้น: ประกอบ component และจัดการการสลับแท็บ
import { mountLinkChecker } from "./components/linkChecker.js";
import { mountQrChecker } from "./components/qrChecker.js";
import { mountNav } from "./nav.js";

mountNav(document.getElementById("nav-actions"));

const tabLink = document.getElementById("tab-link");
const tabQr = document.getElementById("tab-qr");
const panelLink = document.getElementById("panel-link");
const panelQr = document.getElementById("panel-qr");
const resultEl = document.getElementById("result");

// ติดตั้งแต่ละ component (แยกความรับผิดชอบชัดเจน)
const linkComp = mountLinkChecker(panelLink, resultEl);
const qrComp = mountQrChecker(panelQr, resultEl);

function activate(mode) {
  const isLink = mode === "link";
  tabLink.classList.toggle("is-active", isLink);
  tabQr.classList.toggle("is-active", !isLink);
  tabLink.setAttribute("aria-selected", String(isLink));
  tabQr.setAttribute("aria-selected", String(!isLink));
  panelLink.hidden = !isLink;
  panelQr.hidden = isLink;
  resultEl.innerHTML = "";        // ล้างผลเดิมเมื่อสลับโหมด
  // ปิดกล้อง + หยุดรับภาพที่วางด้วย Ctrl+V เมื่อออกจากโหมด QR
  if (isLink) { qrComp.stop(); linkComp.focus(); } else { qrComp.activate(); }
}

tabLink.addEventListener("click", () => activate("link"));
tabQr.addEventListener("click", () => activate("qr"));

activate("link");  // เริ่มที่โหมดตรวจลิงก์
