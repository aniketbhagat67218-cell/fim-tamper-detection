"""
Deterministic security risk analysis engine for inspecting file diffs.
Evaluates security-sensitive patterns without external network calls.
"""
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import config
from core.comparator import ComparisonResult, DiffLine

RISK_DISCLAIMER = (
    "Note: Risk metrics represent deterministic heuristic rule matching. "
    "Triggers flag potential exposure or tampering risks, not definitive malicious intent."
)

@dataclass
class TriggeredRule:
    rule_id: str
    rule_name: str
    category: str
    line_number: Optional[int]
    line_content: str
    description: str
    score: int

@dataclass
class RiskAssessment:
    overall_score: int
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CLEAN"
    triggered_rules: List[TriggeredRule] = field(default_factory=list)
    added_lines_count: int = 0
    deleted_lines_count: int = 0
    summary_text: str = ""
    disclaimer: str = RISK_DISCLAIMER

def analyze_diff_risk(comparison: ComparisonResult, file_path: str = "") -> RiskAssessment:
    """
    Scans added and modified lines for security-critical indicators across
    privilege escalation, firewall disablement, credential leaks, and network tampering.
    """
    if comparison.is_identical or (comparison.added_count == 0 and comparison.deleted_count == 0):
        return RiskAssessment(
            overall_score=0,
            risk_level="CLEAN",
            summary_text="No modifications detected. Integrity verified."
        )

    # If binary file
    if comparison.is_binary:
        score = 25  # Binary modification is medium risk by default
        return RiskAssessment(
            overall_score=score,
            risk_level="MEDIUM",
            triggered_rules=[
                TriggeredRule(
                    rule_id="MED_BINARY_MOD",
                    rule_name="Binary File Modification",
                    category="MEDIUM",
                    line_number=None,
                    line_content="[Binary Data]",
                    description=f"Binary executable/resource changed. Size delta: {comparison.size_delta:+d} bytes.",
                    score=25
                )
            ],
            summary_text=f"Binary asset modified (Size shift: {comparison.size_delta:+d} bytes)."
        )

    triggered: List[TriggeredRule] = []
    total_score = 0

    # 1. Inspect added and modified lines
    added_lines = [line for line in comparison.diff_lines if line.line_type == "+"]

    for diff_line in added_lines:
        content = diff_line.content.strip()
        line_num = diff_line.line_no_new

        # Check HIGH risk rules
        for rule in config.HEURISTIC_RULES["HIGH"]:
            if re.search(rule["pattern"], content):
                tr = TriggeredRule(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    category="HIGH",
                    line_number=line_num,
                    line_content=content[:100],
                    description=rule["description"],
                    score=rule["score"]
                )
                triggered.append(tr)
                total_score += rule["score"]

        # Check MEDIUM risk rules (excluding mass deletion handled separately)
        for rule in config.HEURISTIC_RULES["MEDIUM"]:
            if rule["pattern"] and re.search(rule["pattern"], content):
                tr = TriggeredRule(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    category="MEDIUM",
                    line_number=line_num,
                    line_content=content[:100],
                    description=rule["description"],
                    score=rule["score"]
                )
                triggered.append(tr)
                total_score += rule["score"]

        # Check LOW risk rules
        for rule in config.HEURISTIC_RULES["LOW"]:
            if rule["id"] != "LOW_FORMATTING" and re.search(rule["pattern"], content):
                tr = TriggeredRule(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    category="LOW",
                    line_number=line_num,
                    line_content=content[:100],
                    description=rule["description"],
                    score=rule["score"]
                )
                triggered.append(tr)
                total_score += rule["score"]

    # 2. Check for Mass Deletion Heuristic
    if comparison.old_size > 0 and comparison.deleted_count > 0:
        total_baseline_lines = max(1, len([l for l in comparison.diff_lines if l.line_type in (' ', '-')]))
        deletion_pct = (comparison.deleted_count / total_baseline_lines) * 100
        if deletion_pct >= 35 or comparison.deleted_count >= 40:
            tr = TriggeredRule(
                rule_id="MED_MASS_DELETION",
                rule_name="High-Volume Content Deletion",
                category="MEDIUM",
                line_number=None,
                line_content=f"{comparison.deleted_count} lines removed ({deletion_pct:.1f}%)",
                description=f"Mass deletion of {comparison.deleted_count} lines detected, potentially wiping audit trails or defensive configs.",
                score=20
            )
            triggered.append(tr)
            total_score += 20

    # 3. Critical file path checks (e.g. hosts, passwd, shadow, sudoers, .env)
    path_lower = file_path.lower().replace("\\", "/")
    if any(crit in path_lower for crit in ["/etc/hosts", "drivers/etc/hosts", "sudoers", "shadow", "authorized_keys"]):
        tr = TriggeredRule(
            rule_id="HIGH_CRITICAL_SYSTEM_FILE",
            rule_name="Critical System Target Tampering",
            category="HIGH",
            line_number=None,
            line_content=file_path,
            description="Modification of core operating system security file.",
            score=35
        )
        triggered.append(tr)
        total_score += 35

    # 4. Cap score between 0 and 100
    total_score = min(100, total_score)

    # 5. Determine tier
    has_high = any(t.category == "HIGH" for t in triggered)
    has_med = any(t.category == "MEDIUM" for t in triggered)

    if has_high or total_score >= 50:
        risk_level = "HIGH"
    elif has_med or total_score >= 20:
        risk_level = "MEDIUM"
    elif total_score > 0:
        risk_level = "LOW"
    else:
        # If changed but no specific rules triggered, check if only whitespace
        if comparison.added_count > 0 or comparison.deleted_count > 0:
            risk_level = "LOW"
            total_score = 5
        else:
            risk_level = "CLEAN"
            total_score = 0

    # Summary text
    if risk_level == "HIGH":
        summary = f"CRITICAL: {len(triggered)} suspicious indicator(s) identified. Immediate triage advised."
    elif risk_level == "MEDIUM":
        summary = f"WARNING: {len(triggered)} medium-risk indicator(s) identified. Review configuration delta."
    elif risk_level == "LOW":
        summary = f"INFORMATIONAL: Routine modification detected (+{comparison.added_count} / -{comparison.deleted_count} lines)."
    else:
        summary = "Integrity verified. No suspicious patterns found."

    return RiskAssessment(
        overall_score=total_score,
        risk_level=risk_level,
        triggered_rules=triggered,
        added_lines_count=comparison.added_count,
        deleted_lines_count=comparison.deleted_count,
        summary_text=summary
    )
