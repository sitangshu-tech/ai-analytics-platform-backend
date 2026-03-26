const express = require("express");
const pool = require("../config/db");
const auth = require("../middleware/auth");

const router = express.Router();

router.get("/stats", auth("admin"), async (req, res) => {
  const [users, datasets, reports] = await Promise.all([
    pool.query("SELECT COUNT(*)::int AS count FROM users"),
    pool.query("SELECT COUNT(*)::int AS count FROM datasets"),
    pool.query("SELECT COUNT(*)::int AS count FROM reports"),
  ]);
  res.json({
    users: users.rows[0].count,
    datasets: datasets.rows[0].count,
    reports: reports.rows[0].count,
  });
});

router.get("/users", auth("admin"), async (req, res) => {
  const users = await pool.query(
    "SELECT id,email,role,is_blocked,subscription_plan,usage_count,created_at FROM users ORDER BY id DESC"
  );
  res.json(users.rows);
});

router.patch("/users/:id/block", auth("admin"), async (req, res) => {
  await pool.query("UPDATE users SET is_blocked = NOT is_blocked WHERE id=$1", [req.params.id]);
  res.json({ message: "User status toggled" });
});

router.delete("/users/:id", auth("admin"), async (req, res) => {
  await pool.query("DELETE FROM users WHERE id=$1", [req.params.id]);
  res.json({ message: "User deleted" });
});

router.delete("/datasets/:id", auth("admin"), async (req, res) => {
  await pool.query("DELETE FROM datasets WHERE id=$1", [req.params.id]);
  res.json({ message: "Dataset deleted" });
});

router.delete("/reports/:id", auth("admin"), async (req, res) => {
  await pool.query("DELETE FROM reports WHERE id=$1", [req.params.id]);
  res.json({ message: "Report deleted" });
});

module.exports = router;
