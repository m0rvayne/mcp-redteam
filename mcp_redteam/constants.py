"""Shared constants for mcp-redteam. Centralized for easy tuning."""

# --- File size limits ---
MAX_CONFIG_FILE_BYTES = 10_000_000  # 10MB — prevents OOM from huge config files
MAX_SOURCE_CHARS = 50_000  # 50K chars — LLM context budget for source code

# --- Scan limits ---
MAX_SOURCE_FILES = 10_000  # Cap on file counting to prevent DoS
MAX_FIND_RESULTS = 100  # Cap on find subprocess output lines
SEMGREP_TIMEOUT_SECONDS = 120  # 2 min timeout for semgrep subprocess
LLM_API_TIMEOUT_SECONDS = 60  # 60s timeout for Anthropic API calls

# --- Audit history ---
AUDIT_HISTORY_RETENTION = 20  # Keep last N runs per target

# --- Embedding thresholds ---
EMBEDDING_THRESHOLD_CRITICAL = 0.85  # Cosine similarity > 0.85 = CRITICAL
EMBEDDING_THRESHOLD_HIGH = 0.70  # > 0.70 = HIGH
EMBEDDING_THRESHOLD_MEDIUM = 0.55  # > 0.55 = MEDIUM

# --- Directories to skip ---
SKIP_DIRS = {".venv", "venv", "node_modules", "__pycache__", ".git"}
