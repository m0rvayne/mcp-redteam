// Vulnerable: async function without try/catch
async function handleToolRequest(args) {
  const data = await fetchData(args.url);
  const result = processData(data);
  return { content: result };
}
