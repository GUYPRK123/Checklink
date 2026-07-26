// resultCard.js — component แสดงผลลัพธ์ (ใช้ร่วมกันทั้งโหมดลิงก์และ QR)

const ICONS = {
  green: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
  yellow:'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="13"/><line x1="12" y1="16.5" x2="12" y2="16.5"/>',
  red:   '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/>',
};
const SEV = { critical: "!", high: "!", medium: "?", low: "·", good: "\u2713" };

function esc(s) {
  return String(s).replace(/[&<>"]/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;" }[c]));
}

function anatomyHTML(a, bad) {
  if (!a || (!a.registrable && !a.is_ip)) return "";
  if (a.is_ip) {
    return `<div class="anatomy"><div class="a-label">ส่วนประกอบของลิงก์</div>
      <div class="urlbits"><span class="seg-domain bad">${esc(a.registrable)}</span><span class="seg-path">${esc(a.path||"")}</span></div>
      <div class="a-tag bad"><span class="dot"></span> นี่คือเลข IP ไม่ใช่ชื่อเว็บ</div></div>`;
  }
  const proto = a.protocol_known ? `${esc(a.protocol)}://` : "";
  const sub = a.subdomain ? `<span class="seg-sub">${esc(a.subdomain)}.</span>` : "";
  return `<div class="anatomy">
    <div class="a-label">ส่วนประกอบของลิงก์ — เชื่อ “โดเมนจริง” (ช่องไฮไลต์สีเข้ม) เป็นหลัก อย่าเชื่อคำที่อยู่หน้ามัน</div>
    <div class="urlbits"><span class="seg-proto">${proto}</span>${sub}<span class="seg-domain ${bad?'bad':''}">${esc(a.registrable)}</span><span class="seg-path">${esc(a.path||"")}</span></div>
    <div class="a-tag ${bad?'bad':''}"><span class="dot"></span> โดเมนจริงของลิงก์นี้คือ <strong style="margin-left:4px">${esc(a.registrable)}</strong></div>
  </div>`;
}

function destinationHTML(dest) {
  if (!dest) return "";
  if (dest.blocked) {
    return `<div class="anatomy dest">
      <div class="a-label">เส้นทางปลายทางจริง (ชั้นที่ 3 — ตามลิงก์ที่เปลี่ยนหน้า/redirect)</div>
      <div class="a-tag bad"><span class="dot"></span> ${esc(dest.blocked_reason || "ปลายทางผิดปกติ ไม่อนุญาตให้ตรวจต่อ")}</div>
    </div>`;
  }
  if (!dest.redirected) return "";
  const hops = (dest.chain || []).map((u, i) => `
    <div class="dest-hop"><span class="dest-hop-label">${i === 0 ? "ลิงก์ต้นทาง" : `redirect #${i}`}</span><code>${esc(u)}</code></div>
  `).join('<div class="dest-arrow">↓</div>');
  return `<div class="anatomy dest">
    <div class="a-label">เส้นทางปลายทางจริง (ชั้นที่ 3 — ตามลิงก์ย่อ/redirect แล้ว ${dest.hops} ครั้ง)</div>
    <div class="dest-chain">${hops}</div>
    <div class="a-tag"><span class="dot"></span> ปลายทางจริงคือ <strong style="margin-left:4px">${esc(dest.final_url)}</strong></div>
  </div>`;
}

function layer4HTML(res) {
  const l4 = res.layer4;
  if (!l4 || !l4.ran) return "";  // ข้ามไปเงียบ ๆ ถ้าไม่ได้รันชั้นนี้ (รู้ผลชัดเจนจากชั้นก่อนแล้ว)
  const reasonIds = new Set((res.reasons || []).map(r => r.id));
  const rows = [];

  const age = l4.domain_age || {};
  if (age.checked) {
    const bad = reasonIds.has("domain_very_new");
    const warn = reasonIds.has("domain_new");
    const state = bad ? "bad" : warn ? "warn" : "ok";
    const text = (bad || warn)
      ? `จดทะเบียนเมื่อ ${age.registered_on} (${age.age_days} วันก่อน) — ยังใหม่มาก`
      : `จดทะเบียนมาแล้ว ${age.age_days} วัน (ตั้งแต่ ${age.registered_on})`;
    rows.push(["อายุโดเมน (วันที่จดทะเบียน)", state, text]);
  } else {
    rows.push(["อายุโดเมน (วันที่จดทะเบียน)", "muted", "เช็กไม่ได้ตอนนี้ (นามสกุลนี้ไม่รองรับ หรือเครือข่ายมีปัญหา)"]);
  }

  const ssl = l4.ssl || {};
  if (ssl.checked) {
    const bad = reasonIds.has("ssl_invalid");
    const warn = reasonIds.has("ssl_cert_new");
    const state = bad ? "bad" : warn ? "warn" : "ok";
    const text = bad
      ? `ตรวจสอบใบรับรองไม่ผ่าน (${ssl.error || "ไม่ถูกต้อง"})`
      : warn
        ? `ออกเมื่อไม่กี่วันก่อน (${ssl.not_before || ""})`
        : "ตรวจสอบผ่าน ไม่พบความผิดปกติ";
    rows.push(["ใบรับรอง SSL", state, text]);
  } else {
    rows.push(["ใบรับรอง SSL", "muted", "เช็กไม่ได้ตอนนี้ (ไม่ได้ใช้ https หรือเชื่อมต่อไม่ได้)"]);
  }

  if (l4.content_checked) {
    const contentBad = ["form_action_mismatch", "favicon_brand_mismatch", "content_brand_mismatch"]
      .some(id => reasonIds.has(id));
    rows.push(["เนื้อหาหน้าเว็บจริง", contentBad ? "bad" : "ok",
      contentBad ? "พบรูปแบบที่ผิดปกติ (ดูรายละเอียดด้านล่าง)"
        : "ดึงหน้าเว็บมาตรวจฟอร์ม/ไอคอนแล้ว ไม่พบสิ่งผิดปกติ"]);
  } else {
    rows.push(["เนื้อหาหน้าเว็บจริง", "muted", "เช็กไม่ได้ตอนนี้ (ดึงหน้าเว็บไม่ได้ หรือไม่ใช่หน้า HTML)"]);
  }

  const items = rows.map(([label, state, text]) => `
    <div class="a-tag ${state}"><span class="dot"></span>
      <span><strong>${esc(label)}:</strong> ${esc(text)}</span>
    </div>`).join("");

  return `<div class="anatomy layer4">
    <div class="a-label">ตรวจเชิงลึกเพิ่มเติม (ชั้นที่ 4 — อายุโดเมน / ใบรับรอง SSL / เนื้อหาเว็บจริง)</div>
    ${items}
  </div>`;
}

function deepCheckUpsellHTML(res) {
  const dc = res.deep_check;
  if (!dc || dc.ran !== false || !dc.locked_reason) return "";
  const cta = dc.locked_reason === "login_required"
    ? `<a class="btn secondary" href="account.html">เข้าสู่ระบบ/สมัครฟรี</a>`
    : `<a class="btn secondary" href="premium.html">อัพเกรดพรีเมียม</a>`;
  return `<div class="upsell">
    <p>${esc(dc.message)}</p>
    ${cta}
  </div>`;
}

function reasonsHTML(reasons, color) {
  if (!reasons || !reasons.length) return "";
  const title = color === "green" ? "ทำไมระบบบอกว่าปลอดภัย" : "เหตุผลที่ระบบเตือน";
  const items = reasons.map(r => `
    <div class="reason sev-${r.severity}">
      <span class="r-ico">${SEV[r.severity] || "·"}</span>
      <span><span class="r-title">${esc(r.title)}</span><span class="r-detail">${esc(r.detail)}</span></span>
    </div>`).join("");
  return `<div class="reasons"><h3>${title}</h3>${items}</div>`;
}

function techHTML(res) {
  const a = res.anatomy || {};
  const src = res.verdict.source === "blacklist"
    ? "ฐานข้อมูล สกมช. (ชั้น 1)" : "วิเคราะห์ลิงก์แบบเรียลไทม์ (ชั้น 2)";

  // คำอธิบายประจำแต่ละส่วน: อธิบายว่า "ของจริงต้องเป็นยังไง" ไม่ใช่แค่สะท้อนสิ่งที่ผู้ใช้พิมพ์
  const domainNote = a.is_ip
    ? "ลิงก์นี้ใช้เลข IP แทนชื่อเว็บ — เว็บทางการแทบไม่ทำแบบนี้"
    : "นี่คือส่วนที่บอกว่าเว็บนี้เป็นของใครจริง ๆ ต้องดูจากส่วนท้ายสุดของชื่อเว็บเท่านั้น ปลอมแปลงไม่ได้เพราะต้องจดทะเบียนถูกต้องตามกฎหมาย";
  const subNote = a.subdomain
    ? "ส่วนนี้เจ้าของโดเมนจริงจะตั้งเป็นคำอะไรก็ได้ตามใจ จึงใช้ยืนยันตัวตนไม่ได้ — มิจฉาชีพชอบเอาชื่อแบรนด์มาใส่ตรงนี้ให้ดูเหมือนของจริง"
    : "ลิงก์นี้ไม่มีโดเมนย่อย";
  const protoNote = !a.protocol_known
    ? "ลิงก์ไม่ได้ระบุวิธีเชื่อมต่อ เบราว์เซอร์จะเติมให้เอง"
    : a.protocol === "https"
      ? "เข้ารหัสข้อมูลระหว่างทาง (แต่เว็บหลอกก็ทำ https ได้เหมือนกัน — ไม่ได้แปลว่าเว็บนี้ปลอดภัย)"
      : a.protocol === "http"
        ? "ไม่เข้ารหัส ข้อมูลที่กรอกอาจถูกดักอ่านได้ระหว่างทาง เว็บทางการปัจจุบันใช้ https แทบทั้งหมด"
        : "";

  const rows = [
    ["ที่มาของผล", src, "", ""],
    ["โดเมนจริง (เจ้าของเว็บตัวจริง)", a.registrable || "-",
      a.is_ip ? "warn" : "ok", domainNote],
    ["โดเมนย่อย (ส่วนหน้าที่ปลอมได้)", a.subdomain || "(ไม่มี)",
      a.subdomain ? "" : "", subNote],
  ];
  if (!a.is_ip) {
    rows.push(["นามสกุลโดเมน", a.tld ? "." + a.tld : "-",
      a.tld_risk || "", a.tld_note || ""]);
  }
  rows.push(
    ["โปรโตคอล", a.protocol || "-",
      (a.protocol_known && a.protocol === "http") ? "warn" : "", protoNote],
    ["คะแนนความเสี่ยงรวม", String(res.score), "",
      "รวมจากทุกสัญญาณที่พบ (ตั้งแต่ 2 ขึ้นไป = เสี่ยง, 6 ขึ้นไป = อันตราย)"],
    ["เวลาที่ใช้ตรวจ", `${res.elapsed_ms} ms`, "", ""],
  );
  const d = res.destination;
  if (d && (d.redirected || d.blocked)) {
    rows.push(["ชั้นที่ 3: ตรวจปลายทางจริง", d.blocked ? "บล็อก (ผิดปกติ)" : `เปลี่ยนหน้า ${d.hops} ครั้งก่อนถึงปลายทาง`,
      d.blocked ? "warn" : "", d.blocked ? d.blocked_reason
        : `ปลายทางจริง: ${d.final_url}`]);
  }

  const kv = rows.map(([k, v, c, note]) => `
    <div class="kv">
      <span class="k">${esc(k)}</span><span class="v ${c}">${esc(v)}</span>
      ${note ? `<span class="kv-note">${esc(note)}</span>` : ""}
    </div>`).join("");

  // ถ้ารู้จักแบรนด์ที่เกี่ยวข้อง -> แสดงโดเมนทางการที่ถูกต้องให้เทียบกับลิงก์ที่ตรวจ
  const ref = res.reference;
  const refBox = ref ? `
    <div class="kv-ref ${ref.impersonated ? "bad" : "ok"}">
      <div class="kv-ref-title">${ref.impersonated
        ? `โดเมนทางการที่ถูกต้องของ ${esc(ref.brand)} คือ`
        : `โดเมนนี้อยู่ในรายชื่อโดเมนทางการของ ${esc(ref.brand)}`}</div>
      <div class="kv-ref-domains">${ref.official_domains.map(d => `<code>${esc(d)}</code>`).join(" ")}</div>
      ${ref.impersonated
        ? `<div class="kv-ref-hint">ลิงก์ที่ตรวจใช้โดเมน <strong>${esc(a.registrable || "-")}</strong> ซึ่งไม่ตรงกับรายการข้างต้น</div>`
        : ""}
    </div>` : "";

  return `<details class="tech"><summary>รายละเอียดทางเทคนิค (สำหรับทีม/รายงาน)</summary>
    <div class="techbox">${refBox}${kv}</div></details>`;
}

// แสดงผลลงใน element ที่กำหนด
export function renderResult(container, res) {
  if (!res.ok) {
    container.innerHTML = `<div class="verdict v-yellow"><div class="v-head">
      <div class="v-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICONS.yellow}</svg></div>
      <div><div class="v-word">ตรวจไม่ได้</div><div class="v-sub">${esc(res.error || "เกิดข้อผิดพลาด")}</div></div>
    </div></div>`;
    return;
  }
  const v = res.verdict;
  const bad = v.color === "red";
  container.innerHTML = `
    <div class="verdict v-${v.color}">
      <div class="v-head">
        <div class="v-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICONS[v.color]}</svg></div>
        <div><div class="v-word">${esc(v.label)}</div><div class="v-sub">${esc(v.headline)}</div></div>
      </div>
      <p class="v-msg">${esc(v.message)}</p>
      ${deepCheckUpsellHTML(res)}
      ${anatomyHTML(res.anatomy, bad)}
      ${destinationHTML(res.destination)}
      ${layer4HTML(res)}
      ${reasonsHTML(res.reasons, v.color)}
      ${techHTML(res)}
    </div>`;
  container.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

export function renderLoading(container, text) {
  container.innerHTML = `<div class="card"><div class="loading"><span class="spin"></span> ${esc(text || "กำลังตรวจสอบ...")}</div></div>`;
}
