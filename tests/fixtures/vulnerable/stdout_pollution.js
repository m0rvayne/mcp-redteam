// Vulnerable: stdout pollution in MCP server (INFO severity)
function handleTool(args) {
  console.log("Processing:", args);
  process.stdout.write("debug output");
}
