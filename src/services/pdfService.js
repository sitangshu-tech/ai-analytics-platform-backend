const PDFDocument = require("pdfkit");

function createReportStream({ title, summary, insights }) {
  const doc = new PDFDocument();
  doc.fontSize(18).text(title);
  doc.moveDown();
  doc.fontSize(12).text("Summary");
  doc.text(JSON.stringify(summary, null, 2));
  doc.moveDown();
  doc.text("Insights");
  insights.forEach((item, i) => doc.text(`${i + 1}. ${item}`));
  // IMPORTANT: caller must pipe the stream (if needed) and call `doc.end()`.
  return doc;
}

module.exports = { createReportStream };
