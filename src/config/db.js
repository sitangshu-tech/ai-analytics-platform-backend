const { Pool } = require("pg");
require("dotenv").config();

const rawConnectionString = process.env.DATABASE_URL || "";
// Keep hosted DB SSL enabled, but avoid strict cert validation failures in common PaaS setups.
const connectionString = rawConnectionString.replace(/sslmode=require/gi, "sslmode=no-verify");
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