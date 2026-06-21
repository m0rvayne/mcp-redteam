"""Core data models for mcp-redteam findings and scan results."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from datetime import datetime

from mcp_redteam import __version__


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingCategory(str, Enum):
    """Audit finding categories."""
    security = "security"
    health = "health"
    architecture = "architecture"
    completeness = "completeness"
    config = "config"


class Location(BaseModel):
    """Source code location of a finding."""
    file: str
    line: Optional[int] = None
    end_line: Optional[int] = None
    column: Optional[int] = None
    snippet: Optional[str] = None


class Finding(BaseModel):
    """A single security finding."""
    id: str = Field(description="Rule ID, e.g. MRT001")
    title: str = Field(description="Human-readable title")
    severity: Severity
    category: FindingCategory
    description: str = Field(description="Detailed description of the vulnerability")
    evidence: str = Field(description="Code path or proof")
    location: Optional[Location] = None
    fix: Optional[str] = Field(None, description="Suggested remediation")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Detection confidence (1.0 = deterministic)")
    source: str = Field("semgrep", description="Which engine found this: semgrep, config, llm")

    # SARIF-required fields
    rule_id: Optional[str] = Field(None, description="SARIF rule identifier")

    @property
    def risk_score(self) -> int:
        """Calculate risk score points for this finding."""
        return severity_score(self.severity)


class ScanMetadata(BaseModel):
    """Metadata about the scan run."""
    tool_name: str = "mcp-redteam"
    tool_version: str = __version__
    scan_start: datetime
    scan_end: Optional[datetime] = None
    target_path: str
    mode: str = "deterministic"  # "deterministic" or "hybrid"
    llm_enabled: bool = False
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    semgrep_available: bool = False
    files_scanned: int = 0
    rules_applied: int = 0


class ScanResult(BaseModel):
    """Complete scan result with findings and metadata."""
    metadata: ScanMetadata
    findings: list[Finding] = []

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def risk_score(self) -> int:
        """Total risk score (capped at 100)."""
        return min(100, sum(f.risk_score for f in self.findings))

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        """Group findings by severity."""
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            result[f.severity].append(f)
        return result

    def findings_by_category(self) -> dict[FindingCategory, list[Finding]]:
        """Group findings by category."""
        result: dict[FindingCategory, list[Finding]] = {c: [] for c in FindingCategory}
        for f in self.findings:
            result[f.category].append(f)
        return result


class Rule(BaseModel):
    """A detection rule definition."""
    id: str = Field(description="Rule ID, e.g. MRT001")
    name: str
    description: str
    severity: Severity
    category: FindingCategory
    engine: str = Field("semgrep", description="semgrep, regex, config, llm")


# --- Severity scoring (deterministic, not LLM) ---

SEVERITY_SCORES: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 5,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def severity_score(severity: Severity) -> int:
    """Calculate risk score points for a severity level."""
    return SEVERITY_SCORES.get(severity, 0)


# --- Rule registry ---

RULE_REGISTRY: dict[str, Rule] = {
    "MRT000": Rule(id="MRT000", name="Unknown Rule", description="Semgrep finding with unrecognized rule ID", severity=Severity.INFO, category=FindingCategory.security),
    "MRT001": Rule(id="MRT001", name="Shell Injection", description="Tool argument reaches shell command (subprocess with shell=True)", severity=Severity.CRITICAL, category=FindingCategory.security),
    "MRT002": Rule(id="MRT002", name="Path Traversal", description="Tool argument used in file path without normalization", severity=Severity.HIGH, category=FindingCategory.security),
    "MRT003": Rule(id="MRT003", name="SSRF", description="Tool argument used as URL in HTTP request without validation", severity=Severity.HIGH, category=FindingCategory.security),
    "MRT004": Rule(id="MRT004", name="Eval Injection", description="Tool argument reaches eval()/exec()", severity=Severity.CRITICAL, category=FindingCategory.security),
    "MRT005": Rule(id="MRT005", name="Hardcoded Secret", description="API key, token, or password hardcoded in source", severity=Severity.CRITICAL, category=FindingCategory.security),
    "MRT006": Rule(id="MRT006", name="Stdout Pollution", description="print()/console.log() pollutes JSON-RPC stdio stream", severity=Severity.INFO, category=FindingCategory.health),
    "MRT007": Rule(id="MRT007", name="Missing Error Handling", description="MCP tool function lacks try/except", severity=Severity.HIGH, category=FindingCategory.health),
    "MRT008": Rule(id="MRT008", name="Credential in Response", description="Tool response contains API key/password/token fields", severity=Severity.HIGH, category=FindingCategory.security),
    "MRT009": Rule(id="MRT009", name="Dead Server", description="MCP server configured but not connected", severity=Severity.HIGH, category=FindingCategory.config),
    "MRT010": Rule(id="MRT010", name="Scope Conflict", description="Same server in multiple config scopes with different settings", severity=Severity.MEDIUM, category=FindingCategory.config),
    "MRT011": Rule(id="MRT011", name="Credential in Config", description="Plaintext secret in git-tracked config file", severity=Severity.CRITICAL, category=FindingCategory.config),
    "MRT012": Rule(id="MRT012", name="Unpinned Package", description="npx/uvx without pinned version — supply chain risk", severity=Severity.HIGH, category=FindingCategory.config),
    "MRT013": Rule(id="MRT013", name="Auto-Enable Bypass", description="enableAllProjectMcpServers allows untrusted servers (CVE-2026-21852)", severity=Severity.CRITICAL, category=FindingCategory.config),
    "MRT014": Rule(id="MRT014", name="API Exfiltration Vector", description="ANTHROPIC_BASE_URL override redirects API traffic (CVE-2025-59536)", severity=Severity.CRITICAL, category=FindingCategory.config),
    "MRT015": Rule(id="MRT015", name="Behavioral Mismatch", description="Tool description claims X but code does Y (LLM-detected)", severity=Severity.HIGH, category=FindingCategory.security, engine="llm"),
    "MRT016": Rule(id="MRT016", name="Rug Pull Risk", description="Tool description changed since last scan", severity=Severity.HIGH, category=FindingCategory.security, engine="llm"),
    "MRT017": Rule(id="MRT017", name="Embedding Similarity", description="Tool description embedding similarity anomaly (LLM-detected)", severity=Severity.MEDIUM, category=FindingCategory.security, engine="llm"),
    "MRT018": Rule(id="MRT018", name="Missing Signal Handler", description="MCP server lacks SIGTERM/SIGINT signal handlers for graceful shutdown", severity=Severity.MEDIUM, category=FindingCategory.health),
    "MRT019": Rule(id="MRT019", name="Blocking Sync Call", description="Synchronous HTTP call inside async function blocks the event loop", severity=Severity.HIGH, category=FindingCategory.health),
    "MRT020": Rule(id="MRT020", name="OAuth Overprivilege", description="OAuth scopes request dangerous permissions (gmail.modify, drive.file, admin.*)", severity=Severity.MEDIUM, category=FindingCategory.security),
    "MRT021": Rule(id="MRT021", name="Env Secret No Rotation", description="Secret loaded from env var without expiry/rotation check", severity=Severity.MEDIUM, category=FindingCategory.security),
    "MRT022": Rule(id="MRT022", name="No Timeout HTTP", description="HTTP request without timeout parameter", severity=Severity.MEDIUM, category=FindingCategory.health),
    "MRT023": Rule(id="MRT023", name="No Timeout Subprocess", description="subprocess.run()/Popen() without timeout parameter", severity=Severity.MEDIUM, category=FindingCategory.health),
    "MRT024": Rule(id="MRT024", name="No Timeout Fetch", description="fetch() without AbortSignal timeout", severity=Severity.MEDIUM, category=FindingCategory.health),
    "MRT025": Rule(id="MRT025", name="Dangerous Params", description="Tool input schema contains dangerous parameter names (cmd, exec, eval, code)", severity=Severity.HIGH, category=FindingCategory.security),
    "MRT026": Rule(id="MRT026", name="JS Missing Error Handling", description="Async function without try/catch error handling", severity=Severity.HIGH, category=FindingCategory.health),
    "MRT027": Rule(id="MRT027", name="JS Credential in Response", description="Return object contains credential fields (token, password, secret)", severity=Severity.HIGH, category=FindingCategory.security),
    "MRT028": Rule(id="MRT028", name="No Timeout Spawn", description="spawn()/execFile() without timeout in options", severity=Severity.MEDIUM, category=FindingCategory.health),
    "MRT029": Rule(id="MRT029", name="Over-Privileged Server", description="Remote MCP server exposes excessive number of tools", severity=Severity.HIGH, category=FindingCategory.architecture, engine="remote"),
    "MRT030": Rule(id="MRT030", name="Remote Dangerous Params", description="Remote tool input schema contains dangerous parameter names (cmd, exec, eval, code)", severity=Severity.HIGH, category=FindingCategory.security, engine="remote"),
    "MRT031": Rule(id="MRT031", name="No TLS", description="MCP server uses HTTP without TLS — all traffic including tokens is unencrypted", severity=Severity.CRITICAL, category=FindingCategory.security, engine="remote"),
}
