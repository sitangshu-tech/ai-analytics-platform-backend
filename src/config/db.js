const { Pool } = require("pg");
const dns = require("dns");
require("dotenv").config();

dns.setDefaultResultOrder("ipv4first");

const rawConnectionString = process.env.DATABASE_URL || "";
// Keep hosted DB SSL enabled, but avoid strict cert validation failures in common PaaS setups.
const connectionString = rawConnectionString.replace(/sslmode=require/gi, "sslmode=no-verify");

function assertValidDatabaseUrl(url) {
  if (!url || !String(url).trim()) {
    throw new Error("DATABASE_URL is empty. Set it in Render Environment to your full Supabase Postgres URI (one line).");
  }
  try {
    const normalized = String(url).trim().replace(/^postgresql:\/\//i, "postgres://");
    const u = new URL(normalized);
    const host = u.hostname;
    if (!host || host === "base") {
      throw new Error(
        `DATABASE_URL host looks wrong: "${host}". Copy the full URI from Supabase → Settings → Database → Connection string (URI). Use the pooler host (e.g. …pooler.supabase.com:6543), not a placeholder.`
      );
    }
  } catch (e) {
    if (e instanceof TypeError) {
      throw new Error(
        "DATABASE_URL is not a valid URL. Paste the full postgresql://… string from Supabase in one line (no line breaks)."
      );
    }
    throw e;
  }
}
assertValidDatabaseUrl(connectionString);
const sslRejectUnauthorized = process.env.DB_SSL_REJECT_UNAUTHORIZED === "true";

const pool = new Pool({
  connectionString,
  // Render can fail on IPv6-only resolution for some DB hosts.
  // Force IPv4 DNS family to avoid ENETUNREACH on hosted deploys.
  family: 4,
  connectionTimeoutMillis: 15000,
  keepAlive: true,
  ssl: {
    rejectUnauthorized: sslRejectUnauthorized,
  },
});

module.exports = pool;