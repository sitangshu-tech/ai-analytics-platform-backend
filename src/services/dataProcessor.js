const { parse } = require("csv-parse/sync");
const XLSX = require("xlsx");

function parseFile(file) {
  const name = file.originalname.toLowerCase();
  if (name.endsWith(".csv")) {
    return parse(file.buffer, { columns: true, skip_empty_lines: true });
  }
  if (name.endsWith(".xlsx") || name.endsWith(".xls")) {
    const workbook = XLSX.read(file.buffer, { type: "buffer" });
    const firstSheet = workbook.SheetNames[0];
    return XLSX.utils.sheet_to_json(workbook.Sheets[firstSheet], { defval: null });
  }
  throw new Error("Unsupported file format");
}

function preprocess(rows) {
  if (!rows.length) return { rows: [], summary: {}, insights: [] };
  const columns = Object.keys(rows[0]);
  const numericColumns = [];
  const categoricalColumns = [];

  for (const col of columns) {
    const sample = rows.map((r) => r[col]).filter((v) => v !== null && v !== "" && v !== undefined);
    const numericCount = sample.filter((v) => !Number.isNaN(Number(v))).length;
    if (sample.length && numericCount / sample.length > 0.7) numericColumns.push(col);
    else categoricalColumns.push(col);
  }

  const cleanedRows = rows.map((row) => {
    const next = { ...row };
    for (const col of columns) {
      if (next[col] === "" || next[col] === undefined) next[col] = null;
      if (numericColumns.includes(col) && next[col] !== null) next[col] = Number(next[col]);
    }
    return next;
  });

  const stats = {};
  for (const col of numericColumns) {
    const values = cleanedRows.map((r) => r[col]).filter((v) => typeof v === "number" && !Number.isNaN(v));
    if (!values.length) continue;
    const sum = values.reduce((a, b) => a + b, 0);
    stats[col] = {
      min: Math.min(...values),
      max: Math.max(...values),
      avg: Number((sum / values.length).toFixed(2)),
    };
  }

  const insights = [];
  for (const col of numericColumns.slice(0, 3)) {
    const s = stats[col];
    if (s) insights.push(`${col}: average ${s.avg}, min ${s.min}, max ${s.max}.`);
  }
  if (categoricalColumns.length && numericColumns.length) {
    const cat = categoricalColumns[0];
    const metric = numericColumns[0];
    const group = {};
    for (const row of cleanedRows) {
      const k = row[cat] || "Unknown";
      const v = Number(row[metric]);
      if (Number.isNaN(v)) continue;
      group[k] = (group[k] || 0) + v;
    }
    const sorted = Object.entries(group).sort((a, b) => b[1] - a[1]);
    if (sorted.length) {
      insights.push(`Top ${cat} by ${metric}: ${sorted[0][0]} (${sorted[0][1]}).`);
      insights.push(`Lowest ${cat} by ${metric}: ${sorted[sorted.length - 1][0]} (${sorted[sorted.length - 1][1]}).`);
    }
  }

  const summary = {
    totalRows: cleanedRows.length,
    totalColumns: columns.length,
    numericColumns,
    categoricalColumns,
    stats,
  };

  return { rows: cleanedRows, summary, insights };
}

module.exports = { parseFile, preprocess };
