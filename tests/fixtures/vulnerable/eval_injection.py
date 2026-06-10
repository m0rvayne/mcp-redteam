# FIXTURE: vulnerable
# EXPECTED_RULES: ["MRT004"]
# EXPECTED_SEVERITY: ["CRITICAL"]
# DESCRIPTION: MCP tool with eval() injection.
#   User-controlled expression passed directly to eval().
#   Real-world pattern: "calculator" or "expression evaluator" tools.

from mcp.server.fastmcp import FastMCP

server = FastMCP("calculator")


@server.tool("evaluate")
async def evaluate(expression: str) -> str:
    """Evaluate a mathematical expression and return the result."""
    result = eval(expression)
    return str(result)


@server.tool("compute_formula")
async def compute_formula(formula: str, variables: dict) -> str:
    """Compute a formula with given variables."""
    for name, value in variables.items():
        locals()[name] = value
    result = eval(formula)
    return str(result)


if __name__ == "__main__":
    server.run()
