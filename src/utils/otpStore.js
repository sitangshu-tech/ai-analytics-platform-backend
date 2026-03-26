const otpStore = new Map();

const OTP_TTL_MS = 10 * 60 * 1000;

function otpKey({ purpose, email }) {
  return `${purpose}:${email.toLowerCase().trim()}`;
}

function createOtp({ purpose, email, meta }) {
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  otpStore.set(otpKey({ purpose, email }), {
    otp,
    expiresAt: Date.now() + OTP_TTL_MS,
    meta: meta ?? null,
  });
  return otp;
}

function verifyOtp({ purpose, email, value }) {
  const key = otpKey({ purpose, email });
  const record = otpStore.get(key);
  if (!record) return false;
  if (record.expiresAt < Date.now()) {
    otpStore.delete(key);
    return false;
  }
  const ok = record.otp === String(value);
  if (!ok) return false;
  otpStore.delete(key);
  return record.meta ?? true;
}

module.exports = { createOtp, verifyOtp };
