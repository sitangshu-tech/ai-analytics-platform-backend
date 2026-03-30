const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("../config/db");
const { getSupabaseAdmin } = require("../config/supabase");
const auth = require("../middleware/auth");

const router = express.Router();
const normalizeEmail = (value = "") => value.trim().toLowerCase();

const passwordPolicy = /^(?=.*[A-Z])(?=.*\d).{8,}$/;
const signupTokenTtlSeconds = 10 * 60;
const otpRequestsByEmail = new Map();
const otpRequestsByIp = new Map();
const otpPerMinutePerEmail = 1;
const otpPerHourPerEmail = 5;
const otpPerHourPerIp = 25;

function pruneOldRequests(store, now, windowMs) {
  for (const [key, timestamps] of store.entries()) {
    const fresh = timestamps.filter((ts) => now - ts < windowMs);
    if (!fresh.length) store.delete(key);
    else store.set(key, fresh);
  }
}

function checkAndRecordOtpRateLimit(email, ip) {
  const now = Date.now();
  const oneMinute = 60 * 1000;
  const oneHour = 60 * 60 * 1000;

  pruneOldRequests(otpRequestsByEmail, now, oneHour);
  pruneOldRequests(otpRequestsByIp, now, oneHour);

  const emailEvents = otpRequestsByEmail.get(email) || [];
  const ipEvents = otpRequestsByIp.get(ip) || [];
  const emailLastMinute = emailEvents.filter((ts) => now - ts < oneMinute).length;
  const emailLastHour = emailEvents.length;
  const ipLastHour = ipEvents.length;

  if (emailLastMinute >= otpPerMinutePerEmail) {
    return { blocked: true, message: "Please wait 60 seconds before requesting another OTP." };
  }
  if (emailLastHour >= otpPerHourPerEmail) {
    return { blocked: true, message: "Too many OTP requests for this email. Please try again after 1 hour." };
  }
  if (ipLastHour >= otpPerHourPerIp) {
    return { blocked: true, message: "Too many OTP requests from your network. Please try again after 1 hour." };
  }

  otpRequestsByEmail.set(email, [...emailEvents, now]);
  otpRequestsByIp.set(ip, [...ipEvents, now]);
  return { blocked: false };
}

router.post("/send-otp", async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  if (!email) return res.status(400).json({ message: "Email required" });
  const clientIp = (req.headers["x-forwarded-for"] || req.ip || "unknown").toString().split(",")[0].trim();
  const localLimit = checkAndRecordOtpRateLimit(email, clientIp);
  if (localLimit.blocked) return res.status(429).json({ message: localLimit.message });

  const existingUser = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
  if (existingUser.rows[0]) return res.status(400).json({ message: "Email already registered. Please sign in." });

  const supabase = getSupabaseAdmin();
  if (!supabase) {
    return res.status(500).json({
      message: "Supabase Auth not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY on the backend.",
    });
  }

  // Supabase sends the code in the email only if the Auth email template includes {{ .Token }} (see Supabase → Authentication → Email templates).
  const { error } = await supabase.auth.signInWithOtp({
    email,
    options: {
      shouldCreateUser: true,
    },
  });

  if (error) {
    console.error("signInWithOtp error:", error.message);
    const message = String(error.message || "");
    if (/rate limit/i.test(message)) {
      return res.status(429).json({ message: "Too many OTP requests. Please wait and try again." });
    }
    return res.status(500).json({ message: message || "Failed to send OTP" });
  }

  return res.json({ message: "OTP sent to your email. Please check and verify." });
});

async function verifySupabaseOtp({ supabase, email, otp }) {
  const tryVerify = async (type) => {
    const { error } = await supabase.auth.verifyOtp({ email, token: otp, type });
    return error;
  };
  let err = await tryVerify("email");
  if (err) err = await tryVerify("signup");
  return err;
}

// Step 1: Verify OTP only -> issue short-lived signup token
router.post("/register/verify-otp", async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const otp = (req.body?.otp || "").toString().trim();
  if (!email) return res.status(400).json({ message: "Email required" });
  if (!otp) return res.status(400).json({ message: "OTP required" });

  const existingUser = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
  if (existingUser.rows[0]) return res.status(400).json({ message: "Email already registered. Please sign in." });

  const supabase = getSupabaseAdmin();
  if (!supabase) {
    return res.status(500).json({
      message: "Supabase Auth not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY on the backend.",
    });
  }

  const verifyErr = await verifySupabaseOtp({ supabase, email, otp });

  if (verifyErr) {
    return res.status(400).json({
      message:
        verifyErr.message ||
        "Invalid OTP. Use the 6-digit code from the email (not the long link). If the email has no code, add {{ .Token }} to your Supabase Auth email template.",
    });
  }

  const signupToken = jwt.sign({ purpose: "signup", email }, process.env.JWT_SECRET, { expiresIn: signupTokenTtlSeconds });
  return res.json({ message: "OTP verified", signupToken });
});

// Step 2: Create account with password -> issue app JWT
router.post("/register/complete", async (req, res) => {
  const signupToken = (req.body?.signupToken || "").toString();
  const password = (req.body?.password || "").toString();
  if (!signupToken) return res.status(400).json({ message: "signupToken required" });
  if (!password) return res.status(400).json({ message: "Password required" });
  if (!passwordPolicy.test(password)) {
    return res.status(400).json({ message: "Password must be 8+ chars, 1 uppercase, 1 number" });
  }

  let payload;
  try {
    payload = jwt.verify(signupToken, process.env.JWT_SECRET);
  } catch {
    return res.status(401).json({ message: "Signup token expired. Please request OTP again." });
  }
  if (payload?.purpose !== "signup" || !payload?.email) {
    return res.status(401).json({ message: "Invalid signup token" });
  }

  const email = normalizeEmail(payload.email);
  const dup = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
  if (dup.rows[0]) return res.status(400).json({ message: "Email already registered. Please sign in." });

  const passwordHash = await bcrypt.hash(password, 10);
  const result = await pool.query(
    "INSERT INTO users (email, password, role, subscription_plan, usage_count) VALUES ($1,$2,'user','free',0) RETURNING id,email,role,subscription_plan",
    [email, passwordHash]
  );

  const user = result.rows[0];
  const token = jwt.sign({ id: user.id, role: user.role, email: user.email }, process.env.JWT_SECRET, { expiresIn: "7d" });
  return res.json({ message: "Signup successful", token, user: { id: user.id, email: user.email, role: user.role, plan: user.subscription_plan } });
});

// Backwards compatibility: if older frontend calls /register/verify with password, treat it as verify+complete.
router.post("/register/verify", async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const otp = (req.body?.otp || "").toString().trim();
  const password = (req.body?.password || "").toString();
  if (!email) return res.status(400).json({ message: "Email required" });
  if (!otp) return res.status(400).json({ message: "OTP required" });
  if (!password) return res.status(400).json({ message: "Password required" });

  const supabase = getSupabaseAdmin();
  if (!supabase) {
    return res.status(500).json({
      message: "Supabase Auth not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY on the backend.",
    });
  }
  const verifyErr = await verifySupabaseOtp({ supabase, email, otp });
  if (verifyErr) {
    return res.status(400).json({
      message:
        verifyErr.message ||
        "Invalid OTP. Use the 6-digit code from the email (not the long link). If the email has no code, add {{ .Token }} to your Supabase Auth email template.",
    });
  }

  // Create user immediately
  req.body.signupToken = jwt.sign({ purpose: "signup", email }, process.env.JWT_SECRET, { expiresIn: signupTokenTtlSeconds });
  return router.handle({ ...req, url: "/register/complete", method: "POST" }, res);
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
