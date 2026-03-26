const express = require("express");
const pool = require("../config/db");
const auth = require("../middleware/auth");
const { askGemini } = require("../services/geminiService");

const router = express.Router();

router.post("/:datasetId", auth(), async (req, res) => {
  try {
    const question = (req.body?.question ?? "").toString().trim();
    if (!question) return res.status(400).json({ message: "Question is required" });

    const ds = await pool.query(
      "SELECT * FROM datasets WHERE id=$1 AND user_id=$2",
      [req.params.datasetId, req.user.id]
    );
    const dataset = ds.rows[0];
    if (!dataset) return res.status(404).json({ message: "Dataset not found" });

    // Be defensive about DB column types (jsonb vs text).
    let jsonData = dataset.json_data;
    if (typeof jsonData === "string") {
      try {
        jsonData = JSON.parse(jsonData);
      } catch {
        // Keep as-is; we'll fall back to empty rows.
      }
    }
    const sampleRows = Array.isArray(jsonData) ? jsonData.slice(0, 10) : [];

    const answer = await askGemini({
      question,
      summary: dataset.summary,
      insights: dataset.insights,
      sampleRows,
    });

    await pool.query(
      "INSERT INTO chats (user_id, dataset_id, question, answer) VALUES ($1,$2,$3,$4)",
      [req.user.id, req.params.datasetId, question, answer]
    );
    res.json({ answer });
  } catch (err) {
    console.error("chatRoutes POST /chat/:datasetId error:", err);
    res.status(500).json({ message: "Chat failed" });
  }
});

router.get("/:datasetId", auth(), async (req, res) => {
  const result = await pool.query(
    "SELECT id,question,answer,created_at FROM chats WHERE user_id=$1 AND dataset_id=$2 ORDER BY id ASC",
    [req.user.id, req.params.datasetId]
  );
  res.json(result.rows);
});

module.exports = router;
