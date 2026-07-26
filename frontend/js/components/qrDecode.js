// qrDecode.js — งานฝั่งภาพทั้งหมดของโหมด QR (ถอดรหัส + ย่อภาพ) แยกออกมาจาก UI
//
// ทุกอย่างในไฟล์นี้ทำงานในเบราว์เซอร์ล้วน ๆ ไม่มีการอัปโหลดรูปต้นฉบับขึ้นเซิร์ฟเวอร์
// เซิร์ฟเวอร์ได้รับแค่ "ข้อความที่ถอดได้" กับภาพย่อเล็ก ๆ (เฉพาะตอนผู้ใช้เป็นพรีเมียม)

const canvas = document.createElement("canvas");
const ctx = canvas.getContext("2d", { willReadFrequently: true });

const MAX_CODES_PER_IMAGE = 5;   // กันรูปพิเศษที่ทำให้วนหาไม่จบ
const THUMB_SIZE = 128;          // ภาพย่อสำหรับเก็บลงประวัติ (เล็กพอที่จะใส่ DB ได้สบาย)

function drawToCanvas(source, width, height) {
  canvas.width = width;
  canvas.height = height;
  ctx.drawImage(source, 0, 0, width, height);
  return ctx.getImageData(0, 0, width, height);
}

/**
 * หา QR "ทุกอัน" ในภาพเดียว
 *
 * jsQR หาได้ครั้งละ 1 อันเท่านั้น จึงใช้วิธี: อ่านเจอแล้วทาสีขาวทับตำแหน่งที่เจอ
 * แล้ววนอ่านใหม่ จนกว่าจะไม่เจออีก — ทำให้บอกได้ว่า "รูปนี้มี QR หลายอัน" ซึ่งเป็น
 * กรณีที่ผู้ใช้เลือกผิดอันได้ง่าย และเป็นฐานของฟีเจอร์สแกนหลายอันพร้อมกัน
 */
export function decodeAll(source, width, height) {
  if (!width || !height) return [];
  let imageData = drawToCanvas(source, width, height);
  const found = [];

  for (let i = 0; i < MAX_CODES_PER_IMAGE; i++) {
    const code = window.jsQR(imageData.data, imageData.width, imageData.height);
    if (!code || !code.data) break;
    found.push(code.data);

    const loc = code.location;
    if (!loc) break;
    const xs = [loc.topLeftCorner, loc.topRightCorner, loc.bottomLeftCorner, loc.bottomRightCorner].map(p => p.x);
    const ys = [loc.topLeftCorner, loc.topRightCorner, loc.bottomLeftCorner, loc.bottomRightCorner].map(p => p.y);
    const pad = 4;  // เผื่อขอบเล็กน้อย ไม่งั้นเศษขอบที่เหลือทำให้อ่านซ้ำอันเดิม
    const x = Math.max(0, Math.min(...xs) - pad);
    const y = Math.max(0, Math.min(...ys) - pad);
    const w = Math.min(canvas.width - x, Math.max(...xs) - Math.min(...xs) + pad * 2);
    const h = Math.min(canvas.height - y, Math.max(...ys) - Math.min(...ys) + pad * 2);
    if (w <= 0 || h <= 0) break;

    ctx.fillStyle = "#fff";
    ctx.fillRect(x, y, w, h);
    imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  }
  return found;
}

/** ย่อภาพเป็นสี่เหลี่ยมจัตุรัสเล็ก ๆ คืนเป็น data URI (ใช้เก็บลงประวัติ) */
export function makeThumb(source, width, height) {
  if (!width || !height) return null;
  const thumb = document.createElement("canvas");
  thumb.width = THUMB_SIZE;
  thumb.height = THUMB_SIZE;
  const tctx = thumb.getContext("2d");
  tctx.fillStyle = "#fff";
  tctx.fillRect(0, 0, THUMB_SIZE, THUMB_SIZE);
  // ครอบให้เต็มกรอบโดยรักษาสัดส่วน (ตัดส่วนเกินออก) เพื่อให้ QR อยู่กลางภาพเสมอ
  const scale = Math.max(THUMB_SIZE / width, THUMB_SIZE / height);
  const w = width * scale, h = height * scale;
  tctx.drawImage(source, (THUMB_SIZE - w) / 2, (THUMB_SIZE - h) / 2, w, h);
  try {
    return thumb.toDataURL("image/jpeg", 0.6);
  } catch {
    return null;   // ภาพจากบาง source ทำให้ canvas ติด taint -> ข้ามภาพย่อไป
  }
}

/**
 * โหลดไฟล์รูปให้อยู่ในรูปที่ ctx.drawImage() ใช้ได้
 *
 * สำคัญ: ห้ามใช้ URL.createObjectURL(file) กับ <img src> ที่นี่
 * แอปตั้ง Content-Security-Policy เป็น "img-src 'self' data:" (ดู _security_headers ใน
 * app.py) ซึ่ง "ไม่รวม blob:" เบราว์เซอร์จึงบล็อกรูปที่มาจาก blob: URL ทิ้งเงียบ ๆ ทำให้
 * การอัปโหลด/ลากรูป QR ใช้ไม่ได้เลยตอนเปิดผ่าน Flask (จะไปทำงานเฉพาะตอนเปิดผ่าน
 * Live Server ที่ไม่มี CSP)
 *
 * createImageBitmap() รับ Blob ตรง ๆ ไม่ผ่าน <img src> จึงไม่ติด CSP และเร็วกว่าด้วย
 * ส่วนทางสำรองใช้ data: URI ซึ่ง CSP อนุญาตอยู่แล้ว
 */
export async function loadImage(file) {
  if (typeof createImageBitmap === "function") {
    try {
      return await createImageBitmap(file);
    } catch {
      // เบราว์เซอร์บางตัวไม่รองรับบางฟอร์แมต -> ตกไปใช้ทางสำรองด้านล่าง
    }
  }
  const dataUrl = await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error("อ่านไฟล์รูปนี้ไม่ได้"));
    reader.readAsDataURL(file);
  });
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error("เปิดไฟล์รูปนี้ไม่ได้"));
    img.src = dataUrl;
  });
}

/** ขนาดจริงของภาพ — ImageBitmap ใช้ width/height ส่วน <img> ใช้ naturalWidth/Height */
function sizeOf(img) {
  return [img.naturalWidth || img.width, img.naturalHeight || img.height];
}

/** อ่านไฟล์รูป 1 ไฟล์ -> { codes: [...], thumb } */
export async function decodeFile(file) {
  const img = await loadImage(file);
  try {
    const [w, h] = sizeOf(img);
    const codes = decodeAll(img, w, h);
    return { codes, thumb: codes.length ? makeThumb(img, w, h) : null };
  } finally {
    img.close?.();   // คืนหน่วยความจำของ ImageBitmap (ไม่มีผลกับ <img>)
  }
}

/** ดึงไฟล์รูปออกจากเหตุการณ์ paste (Ctrl+V) — รองรับทั้งภาพจับหน้าจอและภาพที่ก๊อปจากเว็บ */
export function imageFromPaste(event) {
  const items = event.clipboardData?.items || [];
  for (const item of items) {
    if (item.type && item.type.startsWith("image/")) {
      const file = item.getAsFile();
      if (file) return file;
    }
  }
  return null;
}
