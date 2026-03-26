const express = require("express");
const multer = require("multer");
const pool = require("../config/db");
const auth = require("../middleware/auth");
const { parseFile, preprocess } = require("../services/dataProcessor");

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

router.post("/upload", auth(), upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ message: "File required" });
  const parsed = parseFile(req.file);
  const { rows, summary, insights } = preprocess(parsed);
  const result = await pool.query(
    "INSERT INTO datasets (user_id, name, json_data, summary, insights) VALUES ($1,$2,$3,$4,$5) RETURNING *",
    [req.user.id, req.file.originalname, JSON.stringify(rows), JSON.stringify(summary), JSON.stringify(insights)]
  );
  res.json(result.rows[0]);
});

router.get("/", auth(), async (req, res) => {
  const result = await pool.query("SELECT * FROM datasets WHERE user_id=$1 ORDER BY id DESC", [req.user.id]);
  res.json(result.rows);
});

router.get("/:id", auth(), async (req, res) => {
  const result = await pool.query("SELECT * FROM datasets WHERE id=$1 AND user_id=$2", [req.params.id, req.user.id]);
  if (!result.rows[0]) return res.status(404).json({ message: "Dataset not found" });
  res.json(result.rows[0]);
});

module.exports = router;
