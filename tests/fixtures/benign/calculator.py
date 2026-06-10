# FIXTURE: benign
# EXPECTED_RULES: []
# EXPECTED_SEVERITY: []
# DESCRIPTION: Safe MCP calculator tool. Pure arithmetic, no external calls,
#   no eval, no subprocess, no file I/O. Uses ast.literal_eval for safety.

import ast
import operator
from mcp.server.fastmcp import FastMCP

server = FastMCP("safe-calculator")

OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
}


def _safe_eval(node: ast.AST) -> float:
    """Recursively evaluate an AST node containing only arithmetic."""
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return float(node.value)
    if isinstance(node, ast.BinOp) and type(node.op) in OPERATORS:
        left = _safe_eval(node.left)
        right = _safe_eval(node.right)
        return OPERATORS[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in OPERATORS:
        return OPERATORS[type(node.op)](_safe_eval(node.operand))
    raise ValueError(f"Unsupported expression node: {type(node).__name__}")


@server.tool("calculate")
async def calculate(expression: str) -> str:
    """Evaluate a safe arithmetic expression (+-*/%, ** only)."""
    try:
        tree = ast.parse(expression, mode="eval")
        result = _safe_eval(tree)
        return str(result)
    except (ValueError, SyntaxError, TypeError, ZeroDivisionError) as e:
        return f"Error: {e}"


if __name__ == "__main__":
    server.run()
