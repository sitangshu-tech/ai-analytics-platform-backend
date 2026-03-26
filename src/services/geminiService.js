const { GoogleGenerativeAI } = require("@google/generative-ai");

async function askGemini({ question, summary, insights, sampleRows }) {
  if (!process.env.GEMINI_API_KEY) {
    return "Gemini API key is not configured. Add GEMINI_API_KEY in backend .env.";
  }
  const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
  // Model availability differs by API version and Google account.
  // You can override with `GEMINI_MODEL` in backend .env.
  // If the chosen model is unavailable (404), we try a few alternates.
  const candidateModels = [
    process.env.GEMINI_MODEL,
    "gemini-2.0-flash",
    "gemini-2.5-flash",
    "gemini-2.0-pro",
    "gemini-2.5-pro",
    "gemini-pro-latest",
    "gemini-flash-latest",
    // Older candidates (kept as last-resort).
    "gemini-1.5-pro",
    "gemini-1.5-flash-8b",
  ].filter(Boolean);

  const prompt = `
You are a data analyst assistant.
Answer using only this context:
Dataset summary: ${JSON.stringify(summary)}
Insights: ${JSON.stringify(insights)}
Sample rows: ${JSON.stringify(sampleRows)}
Question: ${question}
Keep it concise and practical.
`;
  let lastErr;
  for (const modelName of candidateModels) {
    try {
      const model = genAI.getGenerativeModel({ model: modelName });
      const result = await model.generateContent(prompt);
      return result.response.text();
    } catch (err) {
      lastErr = err;
    }
  }

  // Return a safe error message instead of throwing (prevents /api/chat from 500'ing).
  console.error("askGemini generateContent error (all models failed):", lastErr);
  return `Gemini request failed. ${lastErr?.message ? `(${lastErr.message})` : ""}`.trim();
}

module.exports = { askGemini };
