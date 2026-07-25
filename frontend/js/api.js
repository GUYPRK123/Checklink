// api.js — ตัวกลางคุยกับ backend
//
// เลือก BASE_URL อัตโนมัติ:
//  - ถ้าเปิดหน้าเว็บผ่าน Flask ตรง ๆ (พอร์ต 5000) -> ใช้ origin เดิม (same-origin)
//  - ถ้าเปิดผ่าน localhost/127.0.0.1 พอร์ตอื่น (เช่น Live Server ตอน dev หน้าเว็บ)
//    -> ชี้ไปที่ backend Flask dev server ที่ 127.0.0.1:5000 โดยตรง
//  - กรณีอื่นทั้งหมด (โดเมนจริงตอน production ที่มี Nginx reverse proxy อยู่หน้า Flask
//    เช่นเข้าผ่าน 443/80) -> ต้องเป็น same-origin เสมอ ห้าม hardcode host/port ของ
//    เครื่อง dev ไม่งั้นเบราว์เซอร์ผู้ใช้จะพยายามยิงไปที่ 127.0.0.1 ของเครื่องตัวเอง
const BASE_URL = (() => {
  const loc = window.location;
  if (loc.protocol.startsWith("http") && loc.port === "5000") return "";
  const isLocalDevHost = loc.hostname === "localhost" || loc.hostname === "127.0.0.1";
  if (isLocalDevHost) return "http://127.0.0.1:5000";
  return "";
})();

let _csrfToken = null;

async function getCsrfToken() {
  if (_csrfToken) return _csrfToken;
  const res = await fetch(`${BASE_URL}/api/auth/csrf-token`, { credentials: "include" });
  const data = await res.json();
  _csrfToken = data.csrf_token;
  return _csrfToken;
}

// ใช้กับ endpoint ที่แก้ state ผ่าน session login (register/login/logout/checkout/api-key)
// endpoint /api/check* ไม่ต้องใช้ตัวนี้ (backend ยกเว้น CSRF ไว้ให้รองรับ API key client ภายนอก)
async function authedFetch(path, { method = "POST", body } = {}) {
  const token = await getCsrfToken();
  let res;
  try {
    res = await fetch(`${BASE_URL}${path}`, {
      method,
      credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRFToken": token },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    throw new Error("ต่อ backend ไม่ได้ — ตรวจว่ารัน `python app.py` อยู่");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.ok === false) {
    throw new Error(data.error || `เซิร์ฟเวอร์ตอบกลับผิดพลาด (${res.status})`);
  }
  return data;
}

export async function checkUrl(url) {
  let res;
  try {
    res = await fetch(`${BASE_URL}/api/check`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
  } catch (e) {
    throw new Error(
      "ต่อ backend ไม่ได้ — ตรวจว่ารัน `python app.py` อยู่ แล้วเปิดหน้าเว็บที่ http://127.0.0.1:5000");
  }
  if (res.status === 405) {
    throw new Error(
      "ได้รหัส 405 — คุณกำลังเปิดหน้าเว็บจากเซิร์ฟเวอร์ที่ไม่ใช่ Flask " +
      "(เช่น Live Server) ให้เปิดผ่าน http://127.0.0.1:5000 แทน");
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `เซิร์ฟเวอร์ตอบกลับผิดพลาด (${res.status})`);
  }
  return res.json();
}

export async function checkUrlsBulk(urls) {
  return authedFetch("/api/check/bulk", { body: { urls } });
}

export const auth = {
  me: () => fetch(`${BASE_URL}/api/auth/me`, { credentials: "include" }).then(r => r.json()),
  register: (email, password) => authedFetch("/api/auth/register", { body: { email, password } }),
  login: (email, password) => authedFetch("/api/auth/login", { body: { email, password } }),
  logout: () => authedFetch("/api/auth/logout"),
};

export const billing = {
  plans: () => fetch(`${BASE_URL}/api/billing/plans`, { credentials: "include" }).then(r => r.json()),
  status: () => fetch(`${BASE_URL}/api/billing/status`, { credentials: "include" }).then(r => r.json()),
  checkout: (payload) => authedFetch("/api/billing/checkout", { body: payload }),
  getApiKey: () => fetch(`${BASE_URL}/api/billing/api-key`, { credentials: "include" }).then(r => r.json()),
  createApiKey: () => authedFetch("/api/billing/api-key"),
};

export const history = {
  list: () => fetch(`${BASE_URL}/api/history`, { credentials: "include" }).then(r => r.json()),
  exportUrl: () => `${BASE_URL}/api/history/export`,
};
