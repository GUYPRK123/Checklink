// ตัวช่วยสร้างเอกสารรายงานรูปแบบทางการ (TH Sarabun New, A4, ขอบ 1.5"/1")
const fs = require('fs');
const d = require('docx');
const {
  Paragraph, TextRun, ImageRun, Table, TableRow, TableCell, WidthType, BorderStyle,
  ShadingType, AlignmentType, HeadingLevel, PageBreak, VerticalAlign, TabStopType,
} = d;

const FONT = 'TH Sarabun New';
const MONO = 'Consolas';
const TEXT_W = 11906 - 2160 - 1440; // ความกว้างพื้นที่พิมพ์ (twips) = 8306
const PX_W = 550;                    // ความกว้างพื้นที่พิมพ์โดยประมาณเป็นพิกเซล

const J = AlignmentType.THAI_DISTRIBUTE;

// ---- ข้อความ: รองรับ **ตัวหนา** และ `โค้ด` แบบย่อในสตริงเดียว
function runs(s, base = {}) {
  if (Array.isArray(s)) return s;
  const out = [];
  const re = /(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g;
  let last = 0, m;
  while ((m = re.exec(s))) {
    if (m.index > last) out.push(new TextRun({ text: s.slice(last, m.index), ...base }));
    const t = m[0];
    if (t.startsWith('**')) out.push(new TextRun({ text: t.slice(2, -2), bold: true, ...base }));
    else if (t.startsWith('*')) out.push(new TextRun({ text: t.slice(1, -1), italics: true, ...base }));
    else out.push(new TextRun({ ...base, text: t.slice(1, -1), font: { ascii: MONO, hAnsi: MONO, cs: FONT }, size: Math.round((base.size || 32) * 0.66) }));
    last = m.index + t.length;
  }
  if (last < s.length) out.push(new TextRun({ text: s.slice(last), ...base }));
  return out;
}

// ย่อหน้าเนื้อความ: ย่อบรรทัดแรก 0.5 นิ้ว จัดแบบกระจายไทย
const P = (s, o = {}) => new Paragraph({
  children: runs(s, o.run || {}),
  alignment: o.align ?? J,
  indent: o.noIndent ? undefined : { firstLine: o.firstLine ?? 720, left: o.left },
  spacing: { after: o.after ?? 0, before: o.before ?? 0 },
  keepNext: o.keepNext,
});
const PL = (s, o = {}) => P(s, { ...o, noIndent: true });

// หัวข้อ: บท / หัวข้อหลัก / หัวข้อย่อย
function chapter(no, title) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    pageBreakBefore: true,
    alignment: AlignmentType.CENTER,
    spacing: { after: 360 },
    children: [new TextRun(`บทที่ ${no}`), new TextRun({ text: title, break: 1 })],
  });
}
const H2 = s => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(s)], spacing: { before: 240, after: 60 }, keepNext: true });
const H3 = s => new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun(s)], spacing: { before: 120, after: 0 }, keepNext: true, indent: { left: 360 } });

// หัวเรื่องหน้า (ไม่เข้าสารบัญ)
const FrontTitle = (s, o = {}) => new Paragraph({ style: 'FrontTitle', children: [new TextRun(s)], pageBreakBefore: o.pageBreak ?? true });

// ---- รายการ
const bullet = (s, level = 0) => new Paragraph({ children: runs(s), numbering: { reference: 'bul', level }, alignment: J });
let numSeq = 0;
function numbered(items) {
  const ref = 'num' + (numSeq++ % 40);
  return items.map(s => new Paragraph({ children: runs(s), numbering: { reference: ref, level: 0 }, alignment: J }));
}

// ---- รูปภาพและตาราง พร้อมคำบรรยายแบบมีเลขกำกับ (ภาพที่ 3.1 / ตารางที่ 3.1)
const counters = { fig: {}, tab: {} };
let curChapter = 0;
const setChapter = n => { curChapter = n; };
function nextNo(kind) {
  counters[kind][curChapter] = (counters[kind][curChapter] || 0) + 1;
  return `${curChapter}.${counters[kind][curChapter]}`;
}
function pngSize(file) {
  const b = fs.readFileSync(file);
  return [b.readUInt32BE(16), b.readUInt32BE(20)];
}
function figure(file, caption, o = {}) {
  const [w, h] = pngSize(file);
  const width = o.width || PX_W;
  const height = Math.round(width * h / w);
  const no = nextNo('fig');
  return [
    new Paragraph({
      alignment: AlignmentType.CENTER, spacing: { before: 120 }, keepNext: true,
      children: [new ImageRun({ type: 'png', data: fs.readFileSync(file), transformation: { width, height }, altText: { title: caption, description: caption, name: file } })],
    }),
    new Paragraph({ style: 'FigureCaption', children: [new TextRun({ text: `ภาพที่ ${no} `, bold: true }), new TextRun(caption)] }),
    ...(o.source ? [new Paragraph({ alignment: d.AlignmentType.CENTER, spacing: { before: 0, after: 160 }, children: [new TextRun({ text: 'ที่มา: ', bold: true, size: 28 }), new TextRun({ text: o.source, size: 28 })] })] : []),
  ];
}
// ภาพสองภาพวางคู่กันในตารางไร้เส้น
function figurePair(f1, c1, f2, c2, caption, o = {}) {
  const colW = Math.floor(TEXT_W / 2);
  const cell = (f, c) => {
    const [w, h] = pngSize(f);
    const width = o.width || 260;
    return new TableCell({
      width: { size: colW, type: WidthType.DXA }, borders: NB, verticalAlign: VerticalAlign.TOP,
      children: [
        new Paragraph({ alignment: AlignmentType.CENTER, children: [new ImageRun({ type: 'png', data: fs.readFileSync(f), transformation: { width, height: Math.round(width * h / w) }, altText: { title: c, description: c, name: f } })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: c, size: 28 })] }),
      ],
    });
  };
  const no = nextNo('fig');
  return [
    new Table({ width: { size: TEXT_W, type: WidthType.DXA }, columnWidths: [colW, colW], borders: NB_TABLE, rows: [new TableRow({ cantSplit: true, children: [cell(f1, c1), cell(f2, c2)] })] }),
    new Paragraph({ style: 'FigureCaption', children: [new TextRun({ text: `ภาพที่ ${no} `, bold: true }), new TextRun(caption)] }),
    ...(o.source ? [new Paragraph({ alignment: d.AlignmentType.CENTER, spacing: { before: 0, after: 160 }, children: [new TextRun({ text: 'ที่มา: ', bold: true, size: 28 }), new TextRun({ text: o.source, size: 28 })] })] : []),
  ];
}

const B = { style: BorderStyle.SINGLE, size: 4, color: '7F7F7F' };
const BORDERS = { top: B, bottom: B, left: B, right: B };
const NBX = { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' };
const NB = { top: NBX, bottom: NBX, left: NBX, right: NBX };
const NB_TABLE = { ...NB, insideHorizontal: NBX, insideVertical: NBX };

// ตารางข้อมูล: widths เป็นสัดส่วน (รวมเท่าไรก็ได้) ระบบแปลงให้เต็มความกว้างพื้นที่พิมพ์
function table(caption, header, rows, widths, o = {}) {
  const total = widths.reduce((a, b) => a + b, 0);
  const cols = widths.map(w => Math.floor(TEXT_W * w / total));
  cols[cols.length - 1] += TEXT_W - cols.reduce((a, b) => a + b, 0);
  const size = o.size || 28;
  const cell = (s, i, isHead, rowOpt = {}) => new TableCell({
    width: { size: cols[i], type: WidthType.DXA },
    borders: BORDERS,
    shading: isHead ? { fill: 'D9E2F3', type: ShadingType.CLEAR, color: 'auto' } : (rowOpt.fill ? { fill: rowOpt.fill, type: ShadingType.CLEAR, color: 'auto' } : undefined),
    margins: { top: 40, bottom: 40, left: 100, right: 100 },
    verticalAlign: VerticalAlign.TOP,
    children: String(s).split('\n').map(line => new Paragraph({
      alignment: isHead ? AlignmentType.CENTER : (o.align && o.align[i]) || AlignmentType.LEFT,
      children: runs(line, { size, bold: isHead || rowOpt.bold ? true : undefined }),
    })),
  });
  const no = nextNo('tab');
  const out = [];
  out.push(new Paragraph({ style: 'TableCaption', keepNext: true, children: [new TextRun({ text: `ตารางที่ ${no} `, bold: true }), new TextRun(caption)] }));
  out.push(new Table({
    width: { size: TEXT_W, type: WidthType.DXA }, columnWidths: cols,
    rows: [
      new TableRow({ tableHeader: true, cantSplit: true, children: header.map((h, i) => cell(h, i, true)) }),
      ...rows.map(r => {
        const opt = r.opt || {};
        const cells = r.opt ? r.cells : r;
        return new TableRow({ cantSplit: true, children: cells.map((c, i) => cell(c, i, false, opt)) });
      }),
    ],
  }));
  if (o.source) out.push(new Paragraph({ spacing: { before: 60 }, children: [new TextRun({ text: 'ที่มา: ', bold: true, size: 28 }), new TextRun({ text: o.source, size: 28 })] }));
  out.push(new Paragraph({ children: [], spacing: { after: 120 } }));
  return out;
}

// กล่องตัวอย่าง/ข้อสังเกต (ตารางช่องเดียวมีพื้นหลัง)
function callout(title, lines, o = {}) {
  const fill = o.fill || 'F2F2F2';
  const edge = { style: BorderStyle.SINGLE, size: 18, color: o.edge || '1F3864' };
  return [new Table({
    width: { size: TEXT_W, type: WidthType.DXA }, columnWidths: [TEXT_W],
    rows: [new TableRow({ cantSplit: !o.split, children: [new TableCell({
      width: { size: TEXT_W, type: WidthType.DXA },
      borders: { top: NBX, bottom: NBX, right: NBX, left: edge },
      shading: { fill, type: ShadingType.CLEAR, color: 'auto' },
      margins: { top: 100, bottom: 100, left: 200, right: 160 },
      children: [
        new Paragraph({ children: [new TextRun({ text: title, bold: true })] }),
        ...lines.map(l => (l instanceof Paragraph) ? l : new Paragraph({ alignment: J, children: runs(l) })),
      ],
    })] })],
  }), new Paragraph({ children: [], spacing: { after: 120 } })];
}

// บล็อกโค้ด
function code(lines) {
  return lines.map((l, i) => new Paragraph({
    shading: { fill: 'F2F2F2', type: ShadingType.CLEAR, color: 'auto' },
    indent: { left: 240, right: 120 },
    spacing: { before: i === 0 ? 60 : 0, after: i === lines.length - 1 ? 160 : 0 },
    children: [new TextRun({ text: l || ' ', font: { ascii: MONO, hAnsi: MONO, cs: FONT }, size: 19 })],
  }));
}

// บรรณานุกรม: ย่อหน้าแขวน 0.5 นิ้ว
const ref = s => new Paragraph({ children: runs(s), indent: { left: 720, hanging: 720 }, spacing: { after: 80 }, alignment: AlignmentType.LEFT });

// ช่องให้ผู้จัดทำกรอกเอง (ไฮไลต์เหลือง)
const fill = s => new TextRun({ text: s, highlight: 'yellow' });

const blank = (n = 1) => Array.from({ length: n }, () => new Paragraph({ children: [] }));

module.exports = {
  d, FONT, MONO, TEXT_W, PX_W, J, runs, P, PL, chapter, H2, H3, FrontTitle, bullet, numbered,
  figure, figurePair, table, callout, code, ref, fill, blank, setChapter, BORDERS, NB, NB_TABLE,
};
