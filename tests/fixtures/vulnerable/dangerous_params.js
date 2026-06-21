// Vulnerable: inputSchema with dangerous parameter names
const toolSchema = {
  inputSchema: {
    properties: {
      cmd: { type: "string", description: "Command to run" },
      eval: { type: "string", description: "Expression to evaluate" },
      code: { type: "string", description: "Code to execute" },
    }
  }
};
