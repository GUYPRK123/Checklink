const fs = require('fs');
const L = require('./lib');
const { d, FONT } = L;
const { Document, Packer, Paragraph, TextRun, Header, AlignmentType, PageNumber, NumberFormat, LevelFormat } = d;
const F = require('./front');
const ch1 = require('./ch1'), ch2 = require('./ch2'), ch3 = require('./ch3'), ch4 = require('./ch4');
const { ch5, biblio, appendices } = require('./ch5');

const font = { ascii: FONT, hAnsi: FONT, cs: FONT, eastAsia: FONT };
const PAGE = {
  size: { width: 11906, height: 16838 },
  margin: { top: 2160, left: 2160, right: 1440, bottom: 1440, header: 720, footer: 720 },
};
const pageHeader = () => ({ default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ children: [PageNumber.CURRENT] })] })] }) });

const numbering = {
  config: [
    { reference: 'bul', levels: [
      { level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 1080, hanging: 360 } } } },
      { level: 1, format: LevelFormat.BULLET, text: '–', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 1440, hanging: 360 } } } },
    ] },
    ...Array.from({ length: 40 }, (_, i) => ({ reference: 'num' + i, levels: [
      { level: 0, format: LevelFormat.DECIMAL, text: '%1)', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 1080, hanging: 360 } } } },
    ] })),
  ],
};

const styles = {
  default: {
    document: { run: { font, size: 32, language: { value: 'en-US', bidirectional: 'th-TH' } } },
  },
  paragraphStyles: [
    { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true,
      run: { font, size: 40, bold: true, color: '000000' }, paragraph: { alignment: AlignmentType.CENTER, spacing: { after: 360 }, outlineLevel: 0 } },
    { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true,
      run: { font, size: 36, bold: true, color: '000000' }, paragraph: { spacing: { before: 240, after: 60 }, outlineLevel: 1 } },
    { id: 'Heading3', name: 'Heading 3', basedOn: 'Normal', next: 'Normal', quickFormat: true,
      run: { font, size: 32, bold: true, color: '000000' }, paragraph: { spacing: { before: 120 }, outlineLevel: 2 } },
    { id: 'FrontTitle', name: 'Front Title', basedOn: 'Normal', next: 'Normal',
      run: { font, size: 40, bold: true }, paragraph: { alignment: AlignmentType.CENTER, spacing: { after: 360 } } },
    { id: 'TableCaption', name: 'TableCaption', basedOn: 'Normal', next: 'Normal',
      run: { font, size: 32 }, paragraph: { spacing: { before: 120, after: 60 } } },
    { id: 'FigureCaption', name: 'FigureCaption', basedOn: 'Normal', next: 'Normal',
      run: { font, size: 32 }, paragraph: { alignment: AlignmentType.CENTER, spacing: { before: 60, after: 160 } } },
  ],
};

const doc = new Document({
  creator: 'กลุ่มที่ 34',
  title: 'รายงานโครงงาน เช็กก่อนกด: ระบบตรวจความเสี่ยงลิงก์และ QR Code แบบเรียลไทม์',
  description: 'Check Before Click: Realtime Link Risk Checker',
  features: { updateFields: true },
  styles, numbering,
  sections: [
    { properties: { page: PAGE }, children: F.cover },
    { properties: { page: { ...PAGE, pageNumbers: { start: 1, formatType: NumberFormat.THAI_LETTERS } } }, headers: pageHeader(),
      children: [...F.approval, ...F.abstractTh, ...F.abstractEn, ...F.ack, ...F.tocs] },
    { properties: { page: { ...PAGE, pageNumbers: { start: 1, formatType: NumberFormat.DECIMAL } } }, headers: pageHeader(),
      children: [...ch1(), ...ch2(), ...ch3(), ...ch4(), ...ch5(), ...biblio(), ...appendices()] },
  ],
});

Packer.toBuffer(doc).then(buf => {
  const out = 'รายงานโครงงาน-เช็กก่อนกด.docx';
  fs.writeFileSync(out, buf);
  console.log('wrote', out, buf.length);
});
