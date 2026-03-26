const express = require("express");
const pool = require("../config/db");
const auth = require("../middleware/auth");

const router = express.Router();
const PRICES = { basic: 299, pro: 499 };

router.post("/cashfree/create-order", auth(), async (req, res) => {
  const { plan } = req.body;
  if (!PRICES[plan]) return res.status(400).json({ message: "Invalid plan" });
  const orderId = `order_${req.user.id}_${Date.now()}`;
  res.json({
    orderId,
    amount: PRICES[plan],
    currency: "INR",
    note: "Wire this endpoint with official Cashfree SDK credentials for production checkout session.",
  });
});

router.post("/cashfree/verify", auth(), async (req, res) => {
  const { plan, status } = req.body;
  const amount = PRICES[plan] || 0;
  await pool.query("INSERT INTO payments (user_id, plan, amount, status) VALUES ($1,$2,$3,$4)", [
    req.user.id,
    plan,
    amount,
    status,
  ]);
  if (status === "SUCCESS") {
    await pool.query("UPDATE users SET subscription_plan=$1, usage_count=0 WHERE id=$2", [plan, req.user.id]);
  }
  res.json({ message: "Payment recorded" });
});

module.exports = router;
