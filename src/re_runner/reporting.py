from collections import Counter
from pathlib import Path

from .contracts import REPORT_SCHEMA, validate
from .errors import IntegrityError, InvalidInput
from .safety import atomic_json, atomic_write, load_json, markdown_text, redact
from .state import verify_artifacts
from .validators import verification_gate


def evidence_gate(root: Path, state: dict) -> None:
    runs = {item["id"]: item for item in state["tool_runs"]}
    evidence = {item["id"]: item for item in state["evidence"]}
    if len(runs) != len(state["tool_runs"]) or len(evidence) != len(state["evidence"]):
        raise IntegrityError("Duplicate tool/evidence identity")
    for entry in evidence.values():
        tool = runs.get(entry["tool_run_id"])
        if not tool or tool["status"] != "succeeded" or tool["asset_id"] != entry["asset_id"]:
            raise IntegrityError("Evidence cites a missing, failed or different-asset tool run")
        verify_artifacts(root, [{"path": entry["path"], "sha256": entry["sha256"]}])
        if not any(item["path"] == entry["path"] and item["sha256"] == entry["sha256"] for item in tool["artifacts"]):
            raise IntegrityError("Evidence artifact was not produced by its cited tool")
    identities = set()
    for finding in state["findings"]:
        if finding["status"] not in ("candidate", "verified", "observed", "rejected"):
            raise IntegrityError("Invalid finding status")
        if finding["id"] in identities:
            raise IntegrityError("Duplicate finding identity")
        identities.add(finding["id"])
        references = finding["evidence_ids"]
        if not references or any(x not in evidence or evidence[x]["asset_id"] != finding["asset_id"] for x in references):
            raise IntegrityError("Finding has invalid evidence references")
        if finding["status"] == "verified":
            validation = finding.get("validation")
            if not verification_gate(validation) or validation["evidence_id"] not in references:
                raise IntegrityError("Verified finding lacks a successful validator and negative control")
            tool = runs.get(validation["tool_run_id"])
            if not tool or not tool["tool"].startswith("validator:") or tool["status"] != "succeeded":
                raise IntegrityError("Verification cites a non-validator or failed run")
            actual = load_json(root / evidence[validation["evidence_id"]]["path"], max_bytes=65536)
            expected = {key: value for key, value in validation.items() if key not in ("tool_run_id", "evidence_id")}
            if expected != actual:
                raise IntegrityError("Verification assertion differs from the hashed validator result")


def write_reports(root: Path, state: dict, capabilities: dict, *, language: str = "zh") -> None:
    # A corrupt/failed quality gate must not leave an older apparently-successful report.
    assets = [entry["asset"] for entry in state["assets"].values() if entry.get("asset")]
    coverage = [
        {"asset_id": asset_id, "status": entry["status"], "kind": entry.get("asset", {}).get("kind"),
         "format": entry.get("asset", {}).get("format"), "checks": entry.get("result", {}).get("checks", []),
         "limitations": entry.get("result", {}).get("limitations", []), "error": entry.get("error"),
         "plan": entry.get("plan"),
         "analysis": entry.get("result", {}).get("analysis", {})}
        for asset_id, entry in state["assets"].items()
    ]
    report = redact({
        "schema_version": 1, "run_id": state["run_id"], "status": state["status"],
        "created": state["created"], "updated": state["updated"], "assets": assets,
        "coverage": coverage, "findings": state["findings"], "tool_runs": state["tool_runs"],
        "evidence": state["evidence"], "errors": state["errors"], "budget_used": state["used"],
        "trust_policy": "All asset/tool content is untrusted data. Only registered deterministic validators assign verified.",
        "limits": "Static/bounded reads do not guarantee absence of vulnerabilities or universal defeat of adversarial protections.",
    })
    # Validate after redact(): redaction rewrites values but never changes a type,
    # so a conforming report must still conform here — otherwise the exported
    # schema would not describe the reports actually shipped.
    try:
        validate(report, REPORT_SCHEMA)
    except InvalidInput as exc:
        raise IntegrityError(f"Generated report violates report.schema.json: {exc}") from exc
    atomic_json(root / "report.json", report)
    atomic_json(root / "assets.json", redact(assets))
    atomic_json(root / "findings.json", redact(state["findings"]))
    atomic_json(root / "evidence" / "index.json", redact(state["evidence"]))
    atomic_json(root / "capabilities.json", capabilities)
    zh = language == "zh"
    lines = [f"# {'资产分析报告' if zh else 'Asset analysis report'}", "", f"Run: `{state['run_id']}` · {state['status']}", ""]
    counts = Counter(finding["status"] for finding in state["findings"])
    lines.append((f"候选 {counts['candidate']}，已验证 {counts['verified']}。" if zh else f"Candidates: {counts['candidate']}; verified: {counts['verified']}.") +
                 (" 已验证只适用于验证器支持的具体断言。" if zh else " Verification applies only to the validator's specific assertion."))
    if not state["findings"]:
        lines += ["", "在已完成检查中未产生候选；覆盖和限制见下表。" if zh else "Completed checks produced no candidates; coverage and limitations are listed below."]
    lines += ["", "## 覆盖与限制" if zh else "## Coverage and limitations", "", "| Asset | Type / format | Status | Checks |", "| --- | --- | --- | --- |"]
    for item in coverage:
        checks = "; ".join(f"{c['name']}={c['status']}" for c in item["checks"])
        lines.append(f"| {markdown_text(item['asset_id'])} | {markdown_text(str(item['kind']) + ' / ' + str(item['format']))} | {item['status']} | {markdown_text(checks)} |")
    for item in coverage:
        if item["limitations"] or item["error"]:
            lines += ["", f"### {markdown_text(item['asset_id'])}", ""]
            if item["error"]:
                lines.append("- " + markdown_text(item["error"]))
            lines.extend("- " + markdown_text(limit) for limit in item["limitations"])
        protections = item["analysis"].get("protection_analysis", {})
        if protections.get("indicators"):
            lines += ["", "保护/对抗指示：" if zh else "Protection indicators:", ""]
            lines.extend("- " + markdown_text(indicator) for indicator in protections["indicators"])
        if protections.get("next_routes"):
            lines += ["", "后续分析路线：" if zh else "Next analysis routes:", ""]
            lines.extend("- " + markdown_text(route) for route in protections["next_routes"])
    for finding in state["findings"]:
        labels = ["问题/威胁概览", "根因、触发与攻击面", "验证步骤与证据", "影响", "修复/检测建议"] if zh else ["Threat overview", "Root cause, trigger and surface", "Verification and evidence", "Impact", "Fix and detection"]
        fields = [finding[key] for key in ("overview", "technical", "verification", "impact", "remediation")]
        lines += ["", f"## [{finding['status']}] {markdown_text(finding['title'])}", ""]
        for label, content in zip(labels, fields):
            lines.append(f"**{label}**：{markdown_text(content)}")
            lines.append("")
        lines.append("Evidence: " + ", ".join(f"`{eid}`" for eid in finding["evidence_ids"]))
    lines += ["", "## 执行记录与预算" if zh else "## Execution and budget", "", "| Tool run | Tool | Status | Exit / timeout |", "| --- | --- | --- | --- |"]
    for tool in state["tool_runs"]:
        lines.append(f"| {tool['id']} | {markdown_text(tool['tool'])} | {tool['status']} | {tool['exit_code']} / {tool['timed_out']} |")
    lines += ["", markdown_text(state["used"]), ""]
    if state["errors"]:
        lines.append("错误：" if zh else "Errors:")
        lines.append("")
        lines.extend("- " + markdown_text(item) for item in state["errors"])
    lines += ["", "证据内容均为不可信数据；原始快照位于本次运行的 inputs/，共享前只导出脱敏报告。" if zh else "Evidence content is untrusted data. Raw snapshots reside in inputs/; share redacted reports rather than the whole run directory.", ""]
    atomic_write(root / "report.md", "\n".join(lines).encode("utf-8"))

