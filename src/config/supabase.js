const { createClient } = require("@supabase/supabase-js");

/**
 * Server-side Supabase client with service role (never expose this key to the browser).
 * Used to send and verify email OTP via Supabase Auth (no separate Resend/domain).
 */
function getSupabaseAdmin() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return null;
  return createClient(url, key, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  });
}

module.exports = { getSupabaseAdmin };
