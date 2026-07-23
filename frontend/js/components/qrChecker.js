// qrChecker.js — component โหมด "ตรวจ QR Code"
// อ่าน QR ฝั่งเบราว์เซอร์ด้วย jsQR (ไม่เปิดลิงก์จริง) แล้วส่ง URL ที่ถอดได้ไปตรวจที่ backend
import { checkUrl } from "../api.js";
import { renderResult, renderLoading } from "./resultCard.js";

function looksLikeUrl(text) {
  const t = text.trim();
  if (/^https?:\/\//i.test(t)) return true;
  // โดเมนเปล่า ๆ เช่น example.com/path
  return /^[\w.-]+\.[a-z]{2,}([\/?#]|$)/i.test(t) && !/\s/.test(t);
}

export function mountQrChecker(panel, resultEl) {
  panel.innerHTML = `
    <div class="card">
      <label class="field-label">สแกน QR Code เพื่อตรวจลิงก์ปลายทาง</label>
      <div class="qr-modes">
        <button class="btn secondary" id="qr-upload-btn">อัปโหลดรูป QR</button>
        <button class="btn secondary" id="qr-camera-btn">ใช้กล้อง</button>
        <button class="btn secondary" id="qr-stop-btn" hidden>หยุดกล้อง</button>
      </div>
      <input type="file" id="qr-file" accept="image/*" hidden />
      <div id="qr-drop" class="qr-drop">คลิกเพื่อเลือกรูป หรือ ลากรูป QR Code มาวางที่นี่</div>
      <div id="qr-camera" hidden>
        <div class="qr-video-wrap"><video id="qr-video" playsinline muted></video><div class="qr-scanline"></div></div>
      </div>
      <div class="qr-status" id="qr-status"></div>
      <div class="qr-decoded" id="qr-decoded" hidden></div>
    </div>`;

  const fileInput = panel.querySelector("#qr-file");
  const drop = panel.querySelector("#qr-drop");
  const cameraWrap = panel.querySelector("#qr-camera");
  const video = panel.querySelector("#qr-video");
  const statusEl = panel.querySelector("#qr-status");
  const decodedEl = panel.querySelector("#qr-decoded");
  const uploadBtn = panel.querySelector("#qr-upload-btn");
  const cameraBtn = panel.querySelector("#qr-camera-btn");
  const stopBtn = panel.querySelector("#qr-stop-btn");

  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  let stream = null, rafId = null;

  function setStatus(msg) { statusEl.textContent = msg || ""; }
  function showDecoded(text) { decodedEl.hidden = false; decodedEl.textContent = "เนื้อหาใน QR: " + text; }

  // ---- เมื่อถอด QR ได้แล้ว: เป็นลิงก์ไหม ----
  async function handleDecoded(text) {
    showDecoded(text);
    if (!looksLikeUrl(text)) {
      renderResult(resultEl, { ok: false, error: "QR นี้ไม่ใช่ลิงก์เว็บไซต์ จึงตรวจความเสี่ยงลิงก์ไม่ได้" });
      return;
    }
    renderLoading(resultEl, "ถอดลิงก์จาก QR ได้แล้ว — กำลังตรวจสอบความเสี่ยง...");
    try {
      renderResult(resultEl, await checkUrl(text.trim()));
    } catch (err) {
      renderResult(resultEl, { ok: false, error: err.message });
    }
  }

  // ---- โหมดอัปโหลดรูป ----
  function decodeImageFile(file) {
    if (!file) return;
    setStatus("กำลังอ่าน QR จากรูป...");
    const img = new Image();
    img.onload = () => {
      canvas.width = img.naturalWidth; canvas.height = img.naturalHeight;
      ctx.drawImage(img, 0, 0);
      const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = window.jsQR(data.data, data.width, data.height);
      if (code && code.data) { setStatus("อ่าน QR สำเร็จ"); handleDecoded(code.data); }
      else { setStatus("ไม่พบ QR Code ในรูปนี้ ลองรูปที่ชัดขึ้น"); }
    };
    img.onerror = () => setStatus("เปิดรูปไม่ได้");
    img.src = URL.createObjectURL(file);
  }

  // ---- โหมดกล้อง ----
  async function startCamera() {
    stopCamera();
    cameraWrap.hidden = false; drop.hidden = true; stopBtn.hidden = false;
    setStatus("กำลังเปิดกล้อง... เล็ง QR ให้อยู่ในกรอบ");
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
      video.srcObject = stream;
      await video.play();
      tick();
    } catch (err) {
      setStatus("เปิดกล้องไม่ได้ (ต้องใช้ผ่าน https หรือ localhost และอนุญาตสิทธิ์กล้อง) — ลองอัปโหลดรูปแทน");
      cameraWrap.hidden = true; drop.hidden = false; stopBtn.hidden = true;
    }
  }

  function tick() {
    if (!stream) return;
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      canvas.width = video.videoWidth; canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = window.jsQR(data.data, data.width, data.height);
      if (code && code.data) { setStatus("อ่าน QR สำเร็จ"); stopCamera(); handleDecoded(code.data); return; }
    }
    rafId = requestAnimationFrame(tick);
  }

  function stopCamera() {
    if (rafId) { cancelAnimationFrame(rafId); rafId = null; }
    if (stream) { stream.getTracks().forEach(t => t.stop()); stream = null; }
    video.srcObject = null;
    cameraWrap.hidden = true; drop.hidden = false; stopBtn.hidden = true;
  }

  // ---- เหตุการณ์ ----
  uploadBtn.addEventListener("click", () => { stopCamera(); fileInput.click(); });
  drop.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", e => decodeImageFile(e.target.files[0]));
  drop.addEventListener("dragover", e => { e.preventDefault(); drop.style.borderColor = "var(--brand)"; });
  drop.addEventListener("dragleave", () => { drop.style.borderColor = ""; });
  drop.addEventListener("drop", e => {
    e.preventDefault(); drop.style.borderColor = "";
    decodeImageFile(e.dataTransfer.files[0]);
  });
  cameraBtn.addEventListener("click", startCamera);
  stopBtn.addEventListener("click", () => { stopCamera(); setStatus("ปิดกล้องแล้ว"); });

  // ให้ app.js เรียกปิดกล้องเวลาออกจากแท็บนี้
  return { stop: stopCamera };
}
