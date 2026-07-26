// qrChecker.js — component โหมด "ตรวจ QR Code"
//
// อ่าน QR ฝั่งเบราว์เซอร์ด้วย jsQR (ไม่เปิดลิงก์จริง ไม่อัปโหลดรูปต้นฉบับ) แล้วส่งเฉพาะ
// "ข้อความที่ถอดได้" ไปให้ backend จำแนกและตรวจ
//
// รับภาพได้ 4 ทาง: อัปโหลดไฟล์ / ลากมาวาง / กล้อง / วางภาพจากคลิปบอร์ด (Ctrl+V)
// และรองรับกรณีรูปเดียวมี QR หลายอัน ซึ่งเป็นจุดที่ผู้ใช้เลือกผิดอันได้ง่าย
import { checkQr } from "../api.js";
import { renderResult, renderLoading } from "./resultCard.js";
import { renderQrInfo } from "./qrResult.js";
import { decodeFile, decodeAll, makeThumb, imageFromPaste } from "./qrDecode.js";

function esc(s) {
  return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

export function mountQrChecker(panel, resultEl) {
  panel.innerHTML = `
    <div class="card">
      <label class="field-label">สแกน QR Code เพื่อดูว่าข้างในคืออะไร ก่อนจะกดหรือโอนเงิน</label>
      <div class="qr-modes">
        <button class="btn secondary" id="qr-upload-btn">อัปโหลดรูป QR</button>
        <button class="btn secondary" id="qr-camera-btn">ใช้กล้อง</button>
        <button class="btn secondary" id="qr-stop-btn" hidden>หยุดกล้อง</button>
      </div>
      <input type="file" id="qr-file" accept="image/*" hidden />
      <div id="qr-drop" class="qr-drop">
        คลิกเพื่อเลือกรูป หรือลากรูป QR มาวางที่นี่<br>
        <span class="qr-drop-hint">หรือกด Ctrl+V เพื่อวางภาพที่จับหน้าจอ/ก๊อปมาได้เลย</span>
      </div>
      <div id="qr-camera" hidden>
        <div class="qr-video-wrap"><video id="qr-video" playsinline muted></video><div class="qr-scanline"></div></div>
      </div>
      <div class="qr-status" id="qr-status"></div>
      <div class="qr-picker" id="qr-picker" hidden></div>
    </div>`;

  const fileInput = panel.querySelector("#qr-file");
  const drop = panel.querySelector("#qr-drop");
  const cameraWrap = panel.querySelector("#qr-camera");
  const video = panel.querySelector("#qr-video");
  const statusEl = panel.querySelector("#qr-status");
  const pickerEl = panel.querySelector("#qr-picker");
  const uploadBtn = panel.querySelector("#qr-upload-btn");
  const cameraBtn = panel.querySelector("#qr-camera-btn");
  const stopBtn = panel.querySelector("#qr-stop-btn");

  let stream = null, rafId = null, active = false;

  function setStatus(msg, tone = "") {
    statusEl.textContent = msg || "";
    statusEl.className = `qr-status${tone ? ` is-${tone}` : ""}`;
  }

  // ---- ส่งเนื้อหาที่ถอดได้ไปตรวจที่ backend ----
  async function checkPayload(payload, thumb) {
    renderLoading(resultEl, "อ่าน QR ได้แล้ว — กำลังตรวจสอบเนื้อหาข้างใน...");
    try {
      const data = await checkQr(payload, thumb);
      // QR ที่เป็นลิงก์: โชว์ผลตรวจลิงก์ 4 ชั้นก่อน แล้วต่อด้วยการ์ดอธิบายตัว QR
      // QR ที่ไม่ใช่ลิงก์: มีแต่การ์ด QR (ไม่มีลิงก์ให้ตรวจ)
      resultEl.innerHTML = "";
      if (data.scan) {
        const slot = document.createElement("div");
        resultEl.appendChild(slot);
        renderResult(slot, data.scan);
      }
      const qrSlot = document.createElement("div");
      resultEl.appendChild(qrSlot);
      renderQrInfo(qrSlot, data);
      resultEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
    } catch (err) {
      renderResult(resultEl, { ok: false, error: err.message });
    }
  }

  // ---- จัดการผลการถอด: 0 / 1 / หลายอัน ----
  function handleCodes(codes, thumb) {
    pickerEl.hidden = true;
    pickerEl.innerHTML = "";

    if (!codes.length) {
      setStatus("ไม่พบ QR Code ในรูปนี้ — ลองถ่ายใหม่ให้ QR เต็มกรอบ ชัด ไม่เอียง " +
                "และมีขอบขาวรอบ ๆ หรือครอบตัดรูปให้เหลือเฉพาะ QR แล้วลองอีกครั้ง", "warn");
      return;
    }

    if (codes.length === 1) {
      setStatus("อ่าน QR สำเร็จ", "ok");
      checkPayload(codes[0], thumb);
      return;
    }

    // รูปเดียวมีหลาย QR -> ให้ผู้ใช้เลือกเอง ไม่เดาแทน เพราะเลือกผิดอันคือกดผิดลิงก์
    setStatus(`พบ QR ${codes.length} อันในรูปนี้ — เลือกอันที่ต้องการตรวจ`, "warn");
    pickerEl.hidden = false;
    pickerEl.innerHTML = `
      <div class="qr-picker-label">รูปนี้มี QR หลายอัน ระบบไม่เดาให้ว่าคุณหมายถึงอันไหน</div>
      ${codes.map((c, i) => `
        <button class="qr-pick" data-i="${i}">
          <span class="qr-pick-n">${i + 1}</span>
          <code>${esc(c.length > 90 ? c.slice(0, 90) + "…" : c)}</code>
        </button>`).join("")}`;
    pickerEl.querySelectorAll(".qr-pick").forEach(btn => {
      btn.addEventListener("click", () => {
        pickerEl.querySelectorAll(".qr-pick").forEach(b => b.classList.remove("is-picked"));
        btn.classList.add("is-picked");
        checkPayload(codes[Number(btn.dataset.i)], thumb);
      });
    });
  }

  // ---- รับรูปจากไฟล์ / ลากวาง / คลิปบอร์ด ----
  async function handleFile(file) {
    if (!file) return;
    if (!file.type.startsWith("image/")) {
      setStatus("ไฟล์นี้ไม่ใช่รูปภาพ", "warn");
      return;
    }
    setStatus("กำลังอ่าน QR จากรูป...");
    try {
      const { codes, thumb } = await decodeFile(file);
      handleCodes(codes, thumb);
    } catch (err) {
      setStatus(err.message || "เปิดรูปไม่ได้", "warn");
    }
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
      setStatus("เปิดกล้องไม่ได้ (ต้องใช้ผ่าน https หรือ localhost และอนุญาตสิทธิ์กล้อง) — ลองอัปโหลดรูปแทน", "warn");
      cameraWrap.hidden = true; drop.hidden = false; stopBtn.hidden = true;
    }
  }

  function tick() {
    if (!stream) return;
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      const codes = decodeAll(video, video.videoWidth, video.videoHeight);
      if (codes.length) {
        const thumb = makeThumb(video, video.videoWidth, video.videoHeight);
        stopCamera();
        handleCodes(codes, thumb);
        return;
      }
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
  fileInput.addEventListener("change", e => {
    handleFile(e.target.files[0]);
    e.target.value = "";   // เคลียร์เพื่อให้เลือกไฟล์เดิมซ้ำได้
  });
  drop.addEventListener("dragover", e => { e.preventDefault(); drop.classList.add("is-over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("is-over"));
  drop.addEventListener("drop", e => {
    e.preventDefault(); drop.classList.remove("is-over");
    handleFile(e.dataTransfer.files[0]);
  });
  cameraBtn.addEventListener("click", startCamera);
  stopBtn.addEventListener("click", () => { stopCamera(); setStatus("ปิดกล้องแล้ว"); });

  // วางภาพจากคลิปบอร์ด — ดักที่ document เพราะผู้ใช้ไม่ได้โฟกัสช่องไหนเป็นพิเศษ
  // ทำงานเฉพาะตอนแท็บ QR เปิดอยู่ ไม่งั้นจะไปแย่งการวางของโหมดตรวจลิงก์
  document.addEventListener("paste", e => {
    if (!active) return;
    const file = imageFromPaste(e);
    if (!file) return;
    e.preventDefault();
    stopCamera();
    setStatus("รับภาพจากคลิปบอร์ดแล้ว กำลังอ่าน QR...");
    handleFile(file);
  });

  return {
    stop() { active = false; stopCamera(); },
    activate() { active = true; },
  };
}
