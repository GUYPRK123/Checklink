// วาดผัง/กราฟประกอบรายงานเป็น SVG แล้วแปลงเป็น PNG ด้วย resvg (ฟอนต์ Sarabun)
const { Resvg } = require('@resvg/resvg-js');
const fs = require('fs');

const INK = '#1f2937', MUTED = '#6b7280', LINE = '#9ca3af', NAVY = '#1e3a8a', NAVY_BG = '#eef2ff';
const RED = '#d03b3b', YEL = '#fab219', GRN = '#0ca30c';
const RED_BG = '#fde8e8', YEL_BG = '#fef6e0', GRN_BG = '#e6f6e6';

const esc = s => String(s).replace(/([\u0E48-\u0E4B]?)\u0E33/g, '\u0E4D$1\u0E32').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
function text(x, y, s, o = {}) {
  const { size = 16, weight = 400, fill = INK, anchor = 'middle', family = 'Sarabun' } = o;
  return `<text x="${x}" y="${y}" font-family="${family}" font-size="${size}" font-weight="${weight}" fill="${fill}" text-anchor="${anchor}">${esc(s)}</text>`;
}
function lines(x, y, arr, o = {}) {
  const lh = o.lh || (o.size || 16) * 1.35;
  return arr.map((s, i) => text(x, y + i * lh, s, o)).join('');
}
function box(x, y, w, h, o = {}) {
  const { fill = '#fff', stroke = LINE, r = 10, sw = 1.5, dash } = o;
  return `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${r}" fill="${fill}" stroke="${stroke}" stroke-width="${sw}"${dash ? ` stroke-dasharray="${dash}"` : ''}/>`;
}
function arrow(x1, y1, x2, y2, o = {}) {
  const { color = MUTED, sw = 2, dash } = o;
  return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${color}" stroke-width="${sw}" marker-end="url(#ah)"${dash ? ` stroke-dasharray="${dash}"` : ''}/>`;
}
function pathArrow(d, o = {}) {
  const { color = MUTED, sw = 2 } = o;
  return `<path d="${d}" fill="none" stroke="${color}" stroke-width="${sw}" marker-end="url(#ah)"/>`;
}
function pill(x, y, w, h, label, color, bg) {
  return box(x, y, w, h, { fill: bg, stroke: color, r: h / 2, sw: 2 }) + text(x + w / 2, y + h / 2 + 6, label, { size: 17, weight: 700, fill: color });
}
function svg(w, h, body) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">
<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="${MUTED}"/></marker></defs>
<rect width="${w}" height="${h}" fill="#ffffff"/>${body}</svg>`;
}
function render(name, s, width = 2400) {
  const r = new Resvg(s, {
    fitTo: { mode: 'width', value: width },
    font: {
      fontFiles: ['fonts/Sarabun-Regular.ttf', 'fonts/Sarabun-Bold.ttf'],
      loadSystemFonts: true, defaultFontFamily: 'Sarabun',
    },
  });
  fs.writeFileSync(`img/${name}.png`, r.render().asPng());
  fs.writeFileSync(`img/${name}.svg`, s);
  console.log('ok', name);
}

// ---------------------------------------------------------------- ภาพ: สถาปัตยกรรมระบบ
{
  let b = '';
  // ผู้ใช้
  b += box(20, 170, 180, 170, { fill: '#f9fafb' });
  b += text(110, 205, 'ผู้ใช้งาน', { size: 19, weight: 700 });
  b += lines(110, 235, ['เบราว์เซอร์ / มือถือ', 'หน้าเว็บ HTML + JavaScript', 'ถอด QR จากภาพในเครื่อง', '(jsQR)'], { size: 14, fill: MUTED });
  // ขอบเขต VPS
  b += box(240, 40, 520, 470, { fill: '#fbfbfd', stroke: NAVY, dash: '7 5', r: 14 });
  b += text(260, 68, 'เครื่องแม่ข่าย (VPS) — checkurl.studiodup.com', { size: 15, weight: 700, fill: NAVY, anchor: 'start' });
  b += box(270, 90, 460, 60, { fill: NAVY_BG, stroke: NAVY });
  b += text(500, 116, 'Nginx — Reverse proxy + HTTPS (Let’s Encrypt)', { size: 16, weight: 700, fill: NAVY });
  b += text(500, 138, 'ส่งต่อคำขอไปที่ 127.0.0.1:5000', { size: 13, fill: MUTED });
  b += box(270, 175, 460, 175, { fill: '#fff', stroke: NAVY });
  b += text(500, 200, 'Waitress + Flask (serve.py / app.py)', { size: 16, weight: 700, fill: NAVY });
  const mods = [['check.py', 'ตรวจลิงก์/QR'], ['auth.py', 'สมาชิก'], ['billing.py', 'พรีเมียม'], ['jobs.py', 'งาน bulk']];
  mods.forEach(([m, d], i) => {
    const x = 285 + i * 110;
    b += box(x, 215, 100, 48, { fill: '#f9fafb', r: 6 });
    b += text(x + 50, 236, m, { size: 13, weight: 700 });
    b += text(x + 50, 254, d, { size: 12, fill: MUTED });
  });
  b += box(285, 275, 430, 62, { fill: '#fff7ed', stroke: '#c2410c', r: 6 });
  b += text(500, 299, 'analyzer/ — แกนวิเคราะห์ 4 ชั้น (scanner.py)', { size: 15, weight: 700, fill: '#9a3412' });
  b += text(500, 321, 'url_parser · heuristics · destination · domain_intel · content · qr_payload', { size: 12, fill: MUTED });
  b += box(270, 375, 220, 115, { fill: '#f9fafb' });
  b += text(380, 400, 'SQLite (โหมด WAL)', { size: 15, weight: 700 });
  b += lines(380, 424, ['ผู้ใช้ · ประวัติการตรวจ', 'การชำระเงิน (mock) · API key'], { size: 13, fill: MUTED });
  b += box(510, 375, 220, 115, { fill: '#f9fafb' });
  b += text(620, 400, 'หน่วยความจำของ process', { size: 15, weight: 700 });
  b += lines(620, 424, ['แคชผลตรวจ · คิวงาน bulk', 'โควตาผู้ไม่ล็อกอิน', 'rate limiter'], { size: 13, fill: MUTED });
  b += arrow(200, 255, 268, 125);
  b += text(250, 240, 'HTTPS', { size: 13, fill: MUTED });
  b += arrow(500, 150, 500, 173);
  b += arrow(380, 350, 380, 373);
  b += arrow(620, 350, 620, 373);
  // ภายนอก
  const ext = [
    [85, 'บัญชีดำ สกมช.', 'opendata.ncsa.or.th (แคช 6 ชม.)'],
    [175, 'RDAP (rdap.org)', 'อายุ/ผู้จดทะเบียนโดเมน'],
    [265, 'เว็บปลายทางที่ถูกตรวจ', 'ตาม redirect · TLS · HTML'],
    [355, 'Sandbox (แยกเครื่อง)', 'Chromium ผ่าน Playwright'],
  ];
  ext.forEach(([y, t, d]) => {
    b += box(800, y, 230, 66, { fill: '#f9fafb' });
    b += text(915, y + 28, t, { size: 15, weight: 700 });
    b += text(915, y + 50, d, { size: 12.5, fill: MUTED });
    b += arrow(715, 306, 798, y + 33, { dash: '5 4' });
  });
  b += text(915, 452, 'ทุกคำขอออกนอกผ่าน safe_http.py', { size: 12.5, fill: MUTED });
  b += text(915, 470, '(กัน SSRF / DNS rebinding)', { size: 12.5, fill: MUTED });
  render('fig-architecture', svg(1050, 530, b));
}

// ---------------------------------------------------------------- ภาพ: cascade 4 ชั้น
{
  let b = '';
  b += box(390, 15, 270, 50, { fill: '#f3f4f6' });
  b += text(525, 46, 'ลิงก์ที่ผู้ใช้ส่งมา (หรือลิงก์ใน QR)', { size: 16, weight: 700 });
  const L = [
    ['ชั้น 1', 'เทียบบัญชีดำ สกมช.', ['ค้นใน set ในหน่วยความจำ', 'ตรง = ตัดสินทันที'], '< 1 มิลลิวินาที', 'ทุกคน'],
    ['ชั้น 2', 'วิเคราะห์รูปแบบ URL', ['แบรนด์ปลอม · สะกดเพี้ยน', 'homoglyph · TLD เสี่ยง', 'javascript: · XSS · .apk'], 'ราว 30–80 มิลลิวินาที', 'ทุกคน (ออฟไลน์)'],
    ['ชั้น 3', 'ตามปลายทางจริง', ['ตาม redirect ทีละขั้น', 'วนตรวจชั้น 1–2 ซ้ำ', 'จับการสั่งดาวน์โหลดไฟล์'], '0.3–4 วินาที', 'พรีเมียม'],
    ['ชั้น 4', 'ข้อมูลภายนอก + เนื้อหาเว็บ', ['อายุโดเมน (RDAP) · SSL', 'ฟอร์มขอรหัสผ่าน · แบรนด์', 'สคริปต์อำพราง (sandbox)'], '0.3–4 วินาที (ขนาน)', 'พรีเมียม'],
  ];
  const W = 235, G = 22, X0 = 20, Y = 105;
  L.forEach(([n, t, d, time, who], i) => {
    const x = X0 + i * (W + G);
    const deep = i >= 2;
    b += box(x, Y, W, 210, { fill: deep ? '#fff7ed' : NAVY_BG, stroke: deep ? '#c2410c' : NAVY });
    b += text(x + W / 2, Y + 30, n, { size: 15, weight: 700, fill: deep ? '#9a3412' : NAVY });
    b += text(x + W / 2, Y + 56, t, { size: 17, weight: 700 });
    b += lines(x + W / 2, Y + 88, d, { size: 14, fill: '#374151' });
    b += `<line x1="${x + 15}" y1="${Y + 160}" x2="${x + W - 15}" y2="${Y + 160}" stroke="${LINE}" stroke-width="1"/>`;
    b += text(x + W / 2, Y + 181, 'เวลา: ' + time, { size: 13, fill: MUTED });
    b += text(x + W / 2, Y + 200, 'สิทธิ์: ' + who, { size: 13, fill: MUTED });
    if (i < 3) b += arrow(x + W, Y + 105, x + W + G - 2, Y + 105);
  });
  b += arrow(525, 65, 137, 103);
  // ทางออกก่อนเวลา
  b += text(137, 362, 'ตรงบัญชีดำ → จบ', { size: 13.5, fill: RED, weight: 700 });
  b += text(394, 362, 'ฟันธงได้ (แดง/เขียว) → จบ', { size: 13.5, fill: RED, weight: 700 });
  b += arrow(137, 317, 137, 342, { color: RED });
  b += arrow(394, 317, 394, 342, { color: RED });
  // รวมผล
  b += box(260, 375, 530, 60, { fill: '#f9fafb' });
  b += text(525, 400, 'combos.py — ให้คะแนนเพิ่มกับ "ชุดสัญญาณที่มาด้วยกัน"', { size: 15, weight: 700 });
  b += text(525, 422, 'เช่น อ้างชื่อแบรนด์ + มีช่องรหัสผ่าน → +4 คะแนน', { size: 13, fill: MUTED });
  b += pathArrow('M 908 317 L 908 405 L 792 405');
  b += pathArrow('M 651 317 L 651 373');
  b += box(330, 460, 390, 50, { fill: '#f3f4f6' });
  b += text(525, 491, 'scanner.decide() — สรุปเป็นสีเดียว', { size: 16, weight: 700 });
  b += arrow(525, 435, 525, 458);
  b += pill(265, 530, 150, 40, 'เขียว ปลอดภัย', GRN, GRN_BG);
  b += pill(450, 530, 150, 40, 'เหลือง ระวัง', '#a16207', YEL_BG);
  b += pill(635, 530, 150, 40, 'แดง อันตราย', RED, RED_BG);
  b += arrow(470, 510, 345, 528); b += arrow(525, 510, 525, 528); b += arrow(580, 510, 705, 528);
  render('fig-cascade', svg(1050, 590, b));
}

// ---------------------------------------------------------------- ภาพ: ผังตัดสินสี
{
  let b = '';
  const Q = [
    ['1', 'พบในบัญชีดำ สกมช. ว่าอันตราย?', 'red', 'แดง'],
    ['2', 'บัญชี สกมช. ระบุว่าปลอดภัย?', 'green', 'เขียว'],
    ['3', 'ตรงกับโดเมนทางการของแบรนด์ (BRANDS)?', 'green', 'เขียว'],
    ['4', 'มีสัญญาณระดับ critical หรือคะแนนรวม ≥ 6?', 'red', 'แดง'],
    ['5', 'คะแนนรวม ≥ 2?', 'yellow', 'เหลือง “เสี่ยง”'],
    ['6', 'หลักฐานฝั่งปลอดภัย ≥ 4 และไม่ใช่พื้นที่ฝากเว็บฟรี/ลิงก์ย่อ?', 'green', 'เขียว'],
  ];
  const col = { red: [RED, RED_BG], green: [GRN, GRN_BG], yellow: ['#a16207', YEL_BG] };
  const X = 40, W = 600, H = 56, GAP = 34, Y0 = 20;
  Q.forEach(([n, q, c, lab], i) => {
    const y = Y0 + i * (H + GAP);
    b += box(X, y, W, H, { fill: '#f9fafb', stroke: '#6b7280', r: 8 });
    b += `<circle cx="${X + 28}" cy="${y + H / 2}" r="15" fill="${NAVY}"/>` + text(X + 28, y + H / 2 + 6, n, { size: 15, weight: 700, fill: '#fff' });
    b += text(X + 55, y + H / 2 + 6, q, { size: 16.5, anchor: 'start' });
    b += arrow(X + W, y + H / 2, X + W + 88, y + H / 2, { color: col[c][0] });
    b += text(X + W + 44, y + H / 2 - 8, 'ใช่', { size: 13, fill: col[c][0], weight: 700 });
    b += pill(X + W + 90, y + H / 2 - 20, 190, 40, lab, col[c][0], col[c][1]);
    b += arrow(X + 60, y + H, X + 60, y + H + GAP - 2);
    b += text(X + 90, y + H + 23, 'ไม่', { size: 13, fill: MUTED, weight: 700 });
  });
  const yEnd = Y0 + 6 * (H + GAP);
  b += pill(X, yEnd, 330, 44, 'เหลือง “ระบบยังไม่รู้จักเว็บนี้”', '#a16207', YEL_BG);
  b += text(X + 350, yEnd + 28, '← ค่าเริ่มต้นเมื่อพิสูจน์ไม่ได้ทั้งสองทาง', { size: 14, fill: MUTED, anchor: 'start' });
  render('fig-decision', svg(940, yEnd + 70, b));
}

// ---------------------------------------------------------------- ภาพ: ส่วนประกอบของ URL
{
  let b = '';
  const parts = [
    ['https://', '#e5e7eb', INK, 'โปรโตคอล', 'scheme'],
    ['google.com.', '#e5e7eb', INK, 'โดเมนย่อย', 'เจ้าของตั้งอะไรก็ได้'],
    ['evil.xyz', RED_BG, RED, 'โดเมนจริง (eTLD+1)', 'สิ่งที่ต้องดู'],
    ['/login', '#e5e7eb', INK, 'พาธ', 'path'],
    ['?next=bank', '#e5e7eb', INK, 'พารามิเตอร์', 'query'],
  ];
  const cw = 17.2; let x = 30; const y = 40;
  parts.forEach(([s, bg, fg, l1, l2]) => {
    const w = s.length * cw + 24;
    b += box(x, y, w, 56, { fill: bg, stroke: fg === RED ? RED : '#d1d5db', r: 6, sw: fg === RED ? 2.5 : 1 });
    b += text(x + w / 2, y + 37, s, { size: 26, weight: 700, fill: fg, family: 'DejaVu Sans Mono' });
    b += `<path d="M ${x + 4} ${y + 68} L ${x + 4} ${y + 76} L ${x + w - 4} ${y + 76} L ${x + w - 4} ${y + 68}" fill="none" stroke="${fg === RED ? RED : LINE}" stroke-width="1.5"/>`;
    b += text(x + w / 2, y + 100, l1, { size: 16, weight: 700, fill: fg });
    b += text(x + w / 2, y + 121, l2, { size: 13.5, fill: MUTED });
    x += w + 6;
  });
  b += box(30, 185, x - 36, 80, { fill: '#f9fafb', stroke: '#d1d5db', r: 8 });
  b += text(50, 215, 'คนทั่วไปอ่านจากซ้ายไปขวา เห็นคำว่า “google.com” ก่อนจึงเข้าใจว่าเป็นเว็บของ Google', { size: 15.5, anchor: 'start' });
  b += text(50, 243, 'แต่ผู้ครอบครองลิงก์นี้จริงคือเจ้าของ evil.xyz — ระบบจึงตัดสินจาก “โดเมนจริง” โดยใช้ Public Suffix List', { size: 15.5, anchor: 'start' });
  render('fig-url-anatomy', svg(x + 24, 285, b));
}

// ---------------------------------------------------------------- ภาพ: โครงสร้าง QR พร้อมเพย์
{
  let b = '';
  const T = [
    ['00', '02', '01', 'เวอร์ชันรูปแบบ', '#e5e7eb', INK],
    ['01', '02', '11', 'ชนิด QR (11 = ใช้ซ้ำได้)', '#e5e7eb', INK],
    ['29', '37', '0016A000000677010111 01130066812345678', 'ข้อมูลผู้รับเงิน: รหัสพร้อมเพย์ + เบอร์ 0066812345678', NAVY_BG, NAVY],
    ['53', '03', '764', 'สกุลเงิน (764 = บาท)', '#e5e7eb', INK],
    ['58', '02', 'TH', 'ประเทศ', '#e5e7eb', INK],
    ['63', '04', '823E', 'CRC-16 ค่าตรวจสอบ', RED_BG, RED],
  ];
  b += text(30, 34, 'แต่ละช่องเขียนเป็น  รหัส (ID)  +  ความยาว  +  ค่า   (Tag–Length–Value)', { size: 16, anchor: 'start', weight: 700 });
  T.forEach(([id, len, val, lab, bg, fg], i) => {
    const y = 55 + i * 50;
    b += box(30, y, 55, 38, { fill: '#fff', stroke: '#9ca3af', r: 5 }) + text(57, y + 26, id, { size: 18, weight: 700, family: 'DejaVu Sans Mono' });
    b += box(92, y, 55, 38, { fill: '#fff', stroke: '#9ca3af', r: 5 }) + text(119, y + 26, len, { size: 18, family: 'DejaVu Sans Mono', fill: MUTED });
    b += box(154, y, 420, 38, { fill: bg, stroke: fg === INK ? '#d1d5db' : fg, r: 5 }) + text(164, y + 26, val, { size: 15, family: 'DejaVu Sans Mono', fill: fg, anchor: 'start' });
    b += text(590, y + 25, lab, { size: 15.5, anchor: 'start', fill: fg === INK ? INK : fg, weight: fg === INK ? 400 : 700 });
  });
  b += text(57, 52 + 6 * 50 + 14, 'ID', { size: 12, fill: MUTED }) + text(119, 52 + 6 * 50 + 14, 'ยาว', { size: 12, fill: MUTED }) + text(364, 52 + 6 * 50 + 14, 'ค่า', { size: 12, fill: MUTED });
  b += box(30, 385, 950, 76, { fill: '#fffbeb', stroke: '#d97706', r: 8 });
  b += text(48, 414, 'CRC คำนวณจาก “ทุกไบต์ก่อนหน้า” รวม “6304” (CRC-16/CCITT-FALSE) — ถ้ามีคนแก้เลขบัญชีผู้รับแม้หลักเดียว', { size: 15, anchor: 'start' });
  b += text(48, 440, 'แต่ไม่ได้คำนวณ CRC ใหม่ ค่าจะไม่ตรง ระบบจึงเตือนระดับ critical ได้ทันทีโดยไม่ต้องต่ออินเทอร์เน็ต', { size: 15, anchor: 'start' });
  render('fig-promptpay', svg(1000, 480, b));
}

// ---------------------------------------------------------------- กราฟ: ผลทดสอบ 100 ลิงก์ (ชั้น 1–2)
{
  let b = '';
  const X0 = 190, BW = 640, rows = [
    ['ลิงก์หลอกจริง', '(50 ลิงก์)', [['แดง', 14, RED], ['เหลือง', 36, YEL], ['เขียว', 0, GRN]]],
    ['เว็บไซต์จริง', '(50 ลิงก์)', [['เขียว', 48, GRN], ['เหลือง', 2, YEL], ['แดง', 0, RED]]],
  ];
  b += text(30, 30, 'ผลที่ระบบตอบ แยกตามความจริงของลิงก์ (ชั้น 1–2, ไม่ใช้บัญชีดำ)', { size: 17, weight: 700, anchor: 'start' });
  // แกน
  [0, 10, 20, 30, 40, 50].forEach(v => {
    const x = X0 + v / 50 * BW;
    b += `<line x1="${x}" y1="55" x2="${x}" y2="255" stroke="#e5e7eb" stroke-width="1"/>`;
    b += text(x, 275, v, { size: 13, fill: MUTED });
  });
  b += text(X0 + BW / 2, 300, 'จำนวนลิงก์', { size: 13.5, fill: MUTED });
  rows.forEach(([l1, l2, segs], i) => {
    const y = 75 + i * 95;
    b += text(X0 - 15, y + 26, l1, { size: 16, weight: 700, anchor: 'end' });
    b += text(X0 - 15, y + 48, l2, { size: 13.5, fill: MUTED, anchor: 'end' });
    let x = X0;
    segs.forEach(([lab, v, c]) => {
      if (!v) return;
      const w = v / 50 * BW;
      b += `<rect x="${x}" y="${y}" width="${Math.max(w - 2, 1)}" height="60" rx="4" fill="${c}"/>`;
      const inside = w > 110;
      const tx = inside ? x + w / 2 : x + w + 8;
      b += text(tx, y + 37, `${lab} ${v}`, { size: 15, weight: 700, fill: inside ? (c === YEL ? INK : '#fff') : INK, anchor: inside ? 'middle' : 'start' });
      x += w;
    });
  });
  // คำอธิบายสี
  [['แดง = อันตราย', RED], ['เหลือง = ระวัง/ยังไม่รู้จัก', YEL], ['เขียว = ยืนยันว่าปลอดภัย', GRN]].forEach(([l, c], i) => {
    const x = 190 + i * 245;
    b += `<rect x="${x}" y="320" width="16" height="16" rx="3" fill="${c}"/>` + text(x + 24, 334, l, { size: 14, anchor: 'start' });
  });
  render('fig-eval', svg(930, 355, b));
}

// ---------------------------------------------------------------- กราฟ: เทียบกับ Logistic Regression
{
  let b = '';
  const fps = ['0%', '2%', '6%', '10%', '20%'];
  const ours = [72, 72, 72, 72, 72], lr = [34, 60, 66, 76, 82];
  const X0 = 80, Y0 = 60, H = 260, GW = 150;
  b += text(30, 30, 'ร้อยละของลิงก์หลอกที่จับได้ เมื่อยอมให้เตือนเว็บจริงผิดได้ไม่เกินค่าที่กำหนด', { size: 17, weight: 700, anchor: 'start' });
  [0, 20, 40, 60, 80, 100].forEach(v => {
    const y = Y0 + H - v / 100 * H;
    b += `<line x1="${X0}" y1="${y}" x2="${X0 + GW * 5}" y2="${y}" stroke="${v ? '#e5e7eb' : '#9ca3af'}" stroke-width="1"/>`;
    b += text(X0 - 10, y + 5, v + '%', { size: 13, fill: MUTED, anchor: 'end' });
  });
  fps.forEach((f, i) => {
    const gx = X0 + i * GW + 25;
    [[ours[i], '#2a78d6'], [lr[i], '#eb6834']].forEach(([v, c], j) => {
      const x = gx + j * 52, h = v / 100 * H;
      b += `<path d="M ${x} ${Y0 + H} L ${x} ${Y0 + H - h + 4} Q ${x} ${Y0 + H - h} ${x + 4} ${Y0 + H - h} L ${x + 44} ${Y0 + H - h} Q ${x + 48} ${Y0 + H - h} ${x + 48} ${Y0 + H - h + 4} L ${x + 48} ${Y0 + H} Z" fill="${c}"/>`;
      b += text(x + 24, Y0 + H - h - 8, v + '%', { size: 14, weight: 700 });
    });
    b += text(gx + 50, Y0 + H + 24, 'เตือนผิด ' + f, { size: 14, fill: INK });
  });
  [['ระบบของโครงงาน (ชั้น 1–2)', '#2a78d6'], ['Logistic Regression (ฝึกจาก PhiUSIIL)', '#eb6834']].forEach(([l, c], i) => {
    const x = 120 + i * 330;
    b += `<rect x="${x}" y="${Y0 + H + 45}" width="16" height="16" rx="3" fill="${c}"/>` + text(x + 24, Y0 + H + 59, l, { size: 14, anchor: 'start' });
  });
  render('fig-compare', svg(870, Y0 + H + 80, b));
}

// ---------------------------------------------------------------- ภาพ: ER diagram
{
  let b = '';
  const T = [
    [30, 40, 'users', ['id (PK)', 'email (unique)', 'password_hash', 'plan: free | premium', 'premium_until', 'deep_checks_today', 'created_at']],
    [400, 20, 'scan_history', ['id (PK)', 'user_id (FK)', 'url', 'verdict_color / verdict_label', 'ran_deep_check', 'source: link | qr', 'qr_type · qr_thumb', 'created_at']],
    [400, 300, 'payments', ['id (PK)', 'user_id (FK)', 'method: card | promptpay', 'amount_thb', 'fake_txn_id (mock)', 'created_at']],
    [30, 320, 'api_keys', ['id (PK)', 'user_id (FK)', 'key_hash (SHA-256)', 'key_prefix', 'last_used_at · revoked']],
  ];
  const W = 280;
  T.forEach(([x, y, name, cols]) => {
    const h = 44 + cols.length * 24;
    b += box(x, y, W, h, { fill: '#fff', stroke: NAVY, r: 6 });
    b += `<rect x="${x}" y="${y}" width="${W}" height="36" rx="6" fill="${NAVY}"/>`;
    b += text(x + W / 2, y + 25, name, { size: 16, weight: 700, fill: '#fff', family: 'DejaVu Sans Mono' });
    cols.forEach((c, i) => b += text(x + 14, y + 60 + i * 24, c, { size: 14, anchor: 'start', fill: /PK|FK/.test(c) ? NAVY : INK, weight: /PK|FK/.test(c) ? 700 : 400 }));
  });
  b += pathArrow('M 310 100 L 398 100');
  b += text(354, 92, '1 : N', { size: 13, fill: MUTED });
  b += pathArrow('M 310 180 L 350 180 L 350 380 L 398 380');
  b += text(372, 300, '1 : N', { size: 13, fill: MUTED, anchor: 'start' });
  b += pathArrow('M 170 232 L 170 318');
  b += text(180, 280, '1 : N', { size: 13, fill: MUTED, anchor: 'start' });
  render('fig-er', svg(710, 520, b));
}
