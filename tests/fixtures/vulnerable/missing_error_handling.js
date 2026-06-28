// Vulnerable: MCP tool handler without try/catch
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const server = new McpServer({ name: "test", version: "1.0" });

server.tool("fetch_data", async (args) => {
  const data = await fetchData(args.url);
  const result = processData(data);
  return { content: [{ type: "text", text: result }] };
});
