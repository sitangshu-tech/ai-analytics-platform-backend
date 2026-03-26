require("dotenv").config();
const fs = require("fs");
const path = require("path");
const pool = require("../config/db");

async function run() {
  const schemaPath = path.join(__dirname, "../../db/schema.sql");
  const sql = fs.readFileSync(schemaPath, "utf8");
  await pool.query(sql);
  console.log("Database schema applied successfully.");
  await pool.end();
}

run().catch((error) => {
  console.error("Migration failed:", error.message);
  process.exit(1);
});
