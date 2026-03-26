const express = require("express");
const { PassThrough } = require("stream");
const pool = require("../config/db");
const auth = require("../middleware/auth");
const { createReportStream } = require("../services/pdfService");

const router = express.Router();
const LIMITS = { free: 3, basic: 10, pro: Number.POSITIVE_INFINITY };

function streamToBuffer(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on("data", (c) => chunks.push(c));
    stream.on("end", () => resolve(Buffer.concat(chunks)));
    stream.on("error", reject);
  });
}

router.post("/:datasetId", auth(), async (req, res) => {
  const userRes = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
  const user = userRes.rows[0];
  const limit = LIMITS[user.subscription_plan] || 3;
  if (user.usage_count >= limit) return res.status(403).json({ message: "Report limit reached for this plan" });

  const ds = await pool.query("SELECT * FROM datasets WHERE id=$1 AND user_id=$2", [req.params.datasetId, req.user.id]);
  const dataset = ds.rows[0];
  if (!dataset) return res.status(404).json({ message: "Dataset not found" });

  const fileName = `report-${req.user.id}-${Date.now()}.pdf`;
  const doc = createReportStream({
    title: `Analytics Report - ${dataset.name}`,
    summary: dataset.summary,
    insights: dataset.insights,
  });

  // Ensure data events fire by piping before ending.
  const pass = new PassThrough();
  doc.pipe(pass);
  doc.end();
  const buffer = await streamToBuffer(pass);

  // Save metadata only (DB requires file_url NOT NULL). The actual PDF is returned to the browser.
  await pool.query("INSERT INTO reports (user_id, dataset_id, file_url) VALUES ($1,$2,$3)", [
    req.user.id,
    req.params.datasetId,
    fileName,
  ]);
  await pool.query("UPDATE users SET usage_count=usage_count+1 WHERE id=$1", [req.user.id]);

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
  res.send(buffer);
});

router.get("/", auth(), async (req, res) => {
  const reports = await pool.query("SELECT * FROM reports WHERE user_id=$1 ORDER BY id DESC", [req.user.id]);
  res.json(reports.rows);
});

module.exports = router;
