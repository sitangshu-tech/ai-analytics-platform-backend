/**
 * Sends signup OTP via Resend HTTP API (no SMTP — works reliably on Render/Vercel).
 * https://resend.com/docs/send-with-node
 */

async function sendOtpViaResend({ to, otp, tempPassword }) {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.EMAIL_FROM || "AI Analytics <onboarding@resend.dev>";

  if (!apiKey) {
    return { ok: false, error: "RESEND_API_KEY is not set" };
  }

  const text = [
    `Your signup OTP is: ${otp}. It expires in 10 minutes.`,
    "",
    `Temporary password: ${tempPassword}`,
    "",
    "Please change your password after login.",
  ].join("\n");

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from,
      to: [to],
      subject: "Your signup OTP",
      text,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    return { ok: false, error: `Resend ${res.status}: ${body}` };
  }

  return { ok: true };
}

module.exports = { sendOtpViaResend };
