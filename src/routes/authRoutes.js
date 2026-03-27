const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const pool = require("../config/db");
const { sendOtpViaResend } = require("../services/sendOtpEmail");
const { createOtp, verifyOtp } = require("../utils/otpStore");
const auth = require("../middleware/auth");

const router = express.Router();
const devOtpReturnEnabled = String(process.env.DEV_OTP_RETURN || "").toLowerCase() === "true";
const normalizeEmail = (value = "") => value.trim().toLowerCase();

async function sendOtpEmail({ email, otp, tempPassword }) {
  try {
    const result = await sendOtpViaResend({ to: email, otp, tempPassword });
    if (result.ok) return { sent: true, otp: null };

    console.error("sendOtpEmail error:", result.error);
    if (devOtpReturnEnabled) return { sent: false, otp };
    return { sent: false, otp: null };
  } catch (e) {
    console.error("sendOtpEmail error:", e?.message || e);
    if (devOtpReturnEnabled) return { sent: false, otp };
    return { sent: false, otp: null };
  }
}

router.post("/send-otp", async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  if (!email) return res.status(400).json({ message: "Email required" });
  // Signup OTP only (sign-in uses password).
  const purpose = "register";

  const existingUser = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
  if (existingUser.rows[0]) return res.status(400).json({ message: "Email already registered. Please sign in." });

  const tempPassword = `Temp@${crypto.randomBytes(4).toString("hex")}`; // temp password sent via email
  const otp = createOtp({ purpose, email, meta: { tempPassword } });
  const result = await sendOtpEmail({ email, otp, tempPassword });

  if (result.sent) return res.json({ message: "OTP sent to your email. Please check and verify." });
  if (result.otp) return res.json({ message: "OTP generated (dev). Please use the OTP.", otp: result.otp });
  return res.status(500).json({ message: "Failed to send OTP. Configure Resend (RESEND_API_KEY in backend env)." });
});

// Verify signup OTP -> create account and sign in
router.post("/register/verify", async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const otp = (req.body?.otp || "").toString().trim();
  if (!email) return res.status(400).json({ message: "Email required" });
  if (!otp) return res.status(400).json({ message: "OTP required" });

  // Ensure email isn't already registered
  const existingUser = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
  if (existingUser.rows[0]) return res.status(400).json({ message: "Email already registered. Please sign in." });

  const meta = verifyOtp({ purpose: "register", email, value: otp });
  if (!meta || !meta.tempPassword) return res.status(400).json({ message: "Invalid OTP" });

  const existing = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
  if (existing.rows[0]) return res.status(400).json({ message: "Email already registered" });

  const placeholderPassword = await bcrypt.hash(meta.tempPassword, 10);
  const result = await pool.query(
    "INSERT INTO users (email, password, role, subscription_plan, usage_count) VALUES ($1,$2,'user','free',0) RETURNING id,email,role,subscription_plan",
    [email, placeholderPassword]
  );

  const user = result.rows[0];
  const token = jwt.sign({ id: user.id, role: user.role, email: user.email }, process.env.JWT_SECRET, { expiresIn: "7d" });
  res.json({
    message: "Signup successful",
    token,
    user: { id: user.id, email: user.email, role: user.role, plan: user.subscription_plan },
  });
});

// Sign in with email + password only
router.post("/login", async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = (req.body?.password || "").toString();
  if (!email || !password) return res.status(400).json({ message: "Email and password required" });

  const userRes = await pool.query("SELECT id,email,password,role,is_blocked,subscription_plan FROM users WHERE email=$1", [email]);
  const user = userRes.rows[0];
  if (!user) return res.status(401).json({ message: "Invalid credentials" });
  if (user.is_blocked) return res.status(403).json({ message: "User blocked" });

  let ok = false;
  if (typeof user.password === "string" && user.password.length) {
    // Support legacy plaintext passwords and upgrade them to bcrypt on next successful sign-in.
    if (user.password.startsWith("$2a$") || user.password.startsWith("$2b$") || user.password.startsWith("$2y$")) {
      ok = await bcrypt.compare(password, user.password);
    } else {
      ok = password === user.password;
      if (ok) {
        const newHash = await bcrypt.hash(password, 10);
        await pool.query("UPDATE users SET password=$1 WHERE id=$2", [newHash, user.id]);
      }
    }
  }
  if (!ok) return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign(
    { id: user.id, role: user.role, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ token, user: { id: user.id, email: user.email, role: user.role, plan: user.subscription_plan } });
});

// Authenticated: change password (profile)
router.patch("/change-password", auth(), async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ message: "Current and new password required" });

  // Keep same password policy used during signup.
  if (!/^(?=.*[A-Z])(?=.*\d).{8,}$/.test(newPassword)) {
    return res.status(400).json({ message: "New password must be 8+ chars, 1 uppercase, 1 number" });
  }

  const userRes = await pool.query("SELECT id,password FROM users WHERE id=$1", [req.user.id]);
  const user = userRes.rows[0];
  if (!user) return res.status(404).json({ message: "User not found" });

  const ok = await bcrypt.compare(currentPassword, user.password);
  if (!ok) return res.status(401).json({ message: "Current password is incorrect" });

  const newHash = await bcrypt.hash(newPassword, 10);
  await pool.query("UPDATE users SET password=$1 WHERE id=$2", [newHash, req.user.id]);

  res.json({ message: "Password updated successfully" });
});

module.exports = router;
