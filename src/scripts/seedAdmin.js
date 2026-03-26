require("dotenv").config();
const bcrypt = require("bcryptjs");
const pool = require("../config/db");

async function run() {
  const email = process.env.ADMIN_EMAIL || "admin@example.com";
  const password = process.env.ADMIN_PASSWORD || "Admin1234";
  const hash = await bcrypt.hash(password, 10);
  await pool.query(
    "INSERT INTO users (email,password,role,subscription_plan,usage_count) VALUES ($1,$2,'admin','pro',0) ON CONFLICT (email) DO NOTHING",
    [email, hash]
  );
  console.log("Admin seeded");
  process.exit(0);
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
