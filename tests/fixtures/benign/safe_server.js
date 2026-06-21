// Benign: safe MCP server patterns — should NOT trigger CRITICAL/HIGH
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

async function handleTool(args) {
  try {
    // Safe: literal command, array args, timeout set
    execFile("ls", ["-la", "/tmp"], { timeout: 5000 }, (err, stdout) => {
      if (err) console.error(err);
    });

    // Safe: literal path
    const data = fs.readFileSync("/data/config.json", 'utf8');

    // Safe: hardcoded URL with signal
    const resp = await fetch("https://api.example.com/data", {
      signal: AbortSignal.timeout(5000)
    });

    // Safe: env var for secrets, not hardcoded
    const apiKey = process.env.API_KEY;

    return { result: await resp.json() };
  } catch (err) {
    console.error("Error:", err);
    return { error: "Internal error" };
  }
}
