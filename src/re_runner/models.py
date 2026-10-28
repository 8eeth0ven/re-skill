from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


KINDS = (
    "web", "api", "android", "apple", "binary", "firmware", "source",
    "container", "traffic", "device", "ai", "contract",
)
STATES = (
    "pending", "running", "succeeded", "degraded", "skipped", "blocked",
    "failed", "cancelled",
)


@dataclass
class AssetRequest:
    locator: str
    type: str = "auto"
    id: str | None = None


@dataclass
class Asset:
    id: str
    locator: str
    kind: str
    format: str
    sha256: str | None = None
    snapshot: str | None = None
    parent_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Capability:
    name: str
    available: bool
    version: str | None
    operations: list[str]
    reason: str | None = None


@dataclass
class ToolRun:
    id: str
    asset_id: str
    tool: str
    version: str
    argv: list[str]
    status: str
    started: str
    finished: str
    exit_code: int | None = 0
    stdout: str | None = None
    stderr: str | None = None
    timed_out: bool = False
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None


@dataclass
class Evidence:
    id: str
    asset_id: str
    tool_run_id: str
    path: str
    sha256: str
    location: str
    description: str
    trust: str = "untrusted-data"
    redacted: bool = True


@dataclass
class Finding:
    id: str
    asset_id: str
    rule_id: str
    status: str
    severity: str
    title: str
    overview: str
    technical: str
    verification: str
    impact: str
    remediation: str
    evidence_ids: list[str]
    validation: dict[str, Any] | None = None


@dataclass
class ProfileResult:
    analysis: dict[str, Any] = field(default_factory=dict)
    checks: list[dict[str, str]] = field(default_factory=list)
    candidates: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def check(self, name: str, status: str = "succeeded", detail: str = "") -> None:
        self.checks.append({"name": name, "status": status, "detail": detail})

    def candidate(
        self, rule_id: str, title: str, technical: str, *, location: str,
        severity: str = "medium", impact: str = "Requires contextual verification.",
        remediation: str = "Review the indicated boundary and validate with a controlled test.",
        validation: dict[str, Any] | None = None,
    ) -> None:
        self.candidates.append({
            "rule_id": rule_id, "title": title, "technical": technical,
            "location": location, "severity": severity, "impact": impact,
            "remediation": remediation, "validation": validation,
        })

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
