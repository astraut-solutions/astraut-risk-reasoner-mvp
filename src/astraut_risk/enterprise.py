"""Enterprise controls: policy-as-code checks, hooks, and governance trails."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .models import GovernanceDecision, GovernanceTrail, PolicyCheckResult, RiskAssessment


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _default_policy_checks(
    assessment: RiskAssessment,
    questionnaire: dict[str, dict[str, str]] | None = None,
) -> list[PolicyCheckResult]:
    """Run built-in deterministic policy-as-code checks."""
    questionnaire = questionnaire or {}
    technical = questionnaire.get("technical_architecture", {})
    business = questionnaire.get("business", {})

    signal_ids = {signal.signal_id for signal in assessment.matched_signals}
    results: list[PolicyCheckResult] = []

    mfa_ok = technical.get("mfa_enforced") == "yes" and "no_mfa" not in signal_ids
    results.append(
        PolicyCheckResult(
            policy_id="POL-001",
            title="Privileged MFA Required",
            severity="high",
            status="pass" if mfa_ok else "fail",
            rationale=(
                "Privileged authentication posture meets MFA baseline."
                if mfa_ok
                else "MFA is missing or contradicted by detected signals."
            ),
            evidence=[
                f"questionnaire.technical_architecture.mfa_enforced={technical.get('mfa_enforced', 'unknown')}",
                f"signal.no_mfa_present={str('no_mfa' in signal_ids).lower()}",
            ],
        )
    )

    api_public = technical.get("public_api") == "yes" or "public_api" in signal_ids
    logging_ok = technical.get("logging_monitoring") == "yes" and "no_logging" not in signal_ids
    api_policy_ok = (not api_public) or logging_ok
    results.append(
        PolicyCheckResult(
            policy_id="POL-002",
            title="Public API Requires Logging",
            severity="high",
            status="pass" if api_policy_ok else "fail",
            rationale=(
                "Public API exposure is paired with centralized monitoring controls."
                if api_policy_ok
                else "Public API is exposed without proven logging/monitoring controls."
            ),
            evidence=[
                f"api_public={str(api_public).lower()}",
                f"technical_architecture.logging_monitoring={technical.get('logging_monitoring', 'unknown')}",
            ],
        )
    )

    high_sensitivity = business.get("data_sensitivity") == "high"
    backup_ok = technical.get("backup_restore_tested") == "yes" and "no_tested_backups" not in signal_ids
    backup_policy_ok = (not high_sensitivity) or backup_ok
    results.append(
        PolicyCheckResult(
            policy_id="POL-003",
            title="High Sensitivity Data Requires Tested Backups",
            severity="medium",
            status="pass" if backup_policy_ok else "fail",
            rationale=(
                "Recovery readiness matches high-sensitivity data handling."
                if backup_policy_ok
                else "High-sensitivity data is present without tested backup restore evidence."
            ),
            evidence=[
                f"business.data_sensitivity={business.get('data_sensitivity', 'unknown')}",
                f"technical_architecture.backup_restore_tested={technical.get('backup_restore_tested', 'unknown')}",
            ],
        )
    )

    return results


def load_policy_pack(path: str) -> dict[str, Any]:
    """Load a policy pack YAML document."""
    file = Path(path).expanduser().resolve()
    if not file.exists():
        raise ValueError(f"Policy pack not found: {file}")
    try:
        payload = yaml.safe_load(file.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"Invalid policy pack YAML: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Policy pack must be a YAML object.")
    rules = payload.get("rules")
    if not isinstance(rules, list):
        raise ValueError("Policy pack must define a 'rules' list.")
    return payload


def _context_get(context: dict[str, Any], path: str) -> Any:
    value: Any = context
    for part in path.split("."):
        if isinstance(value, dict):
            if part not in value:
                return None
            value = value[part]
            continue
        return None
    return value


def _coerce_number(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _eval_condition(left: Any, op: str, right: Any) -> bool:
    operator = (op or "").strip().lower()
    if isinstance(left, str) and isinstance(right, bool):
        lowered = left.strip().lower()
        if lowered in {"yes", "no"}:
            right = "yes" if right else "no"
    if isinstance(right, str) and isinstance(left, bool):
        lowered = right.strip().lower()
        if lowered in {"yes", "no"}:
            left = "yes" if left else "no"
    if operator in {"equals", "eq", "=="}:
        return left == right
    if operator in {"not_equals", "ne", "!="}:
        return left != right
    if operator == "contains":
        if isinstance(left, (list, tuple, set, str)):
            return right in left
        return False
    if operator == "in":
        if isinstance(right, (list, tuple, set, str)):
            return left in right
        return False
    if operator in {"lt", "<", "lte", "<=", "gt", ">", "gte", ">="}:
        left_num = _coerce_number(left)
        right_num = _coerce_number(right)
        if left_num is None or right_num is None:
            return False
        if operator in {"lt", "<"}:
            return left_num < right_num
        if operator in {"lte", "<="}:
            return left_num <= right_num
        if operator in {"gt", ">"}:
            return left_num > right_num
        return left_num >= right_num
    raise ValueError(f"Unsupported operator: {op}")


def _evaluate_pack_rules(
    rules: list[dict[str, Any]],
    context: dict[str, Any],
) -> list[PolicyCheckResult]:
    results: list[PolicyCheckResult] = []
    for index, rule in enumerate(rules, start=1):
        policy_id = str(rule.get("id", f"CUSTOM-{index:03d}")).strip() or f"CUSTOM-{index:03d}"
        title = str(rule.get("title", f"Custom policy {index}")).strip()
        severity = str(rule.get("severity", "medium")).strip().lower() or "medium"
        rationale_pass = str(rule.get("rationale_pass", "Custom policy conditions satisfied.")).strip()
        rationale_fail = str(rule.get("rationale_fail", "Custom policy conditions not satisfied.")).strip()
        conditions = rule.get("conditions", [])
        if not isinstance(conditions, list) or not conditions:
            raise ValueError(f"Policy {policy_id} must define a non-empty 'conditions' list.")

        all_ok = True
        evidence: list[str] = []
        for condition in conditions:
            if not isinstance(condition, dict):
                raise ValueError(f"Policy {policy_id} has invalid condition entry.")
            path = str(condition.get("path", "")).strip()
            op = str(condition.get("op", "equals")).strip()
            expected = condition.get("value")
            if not path:
                raise ValueError(f"Policy {policy_id} has condition without path.")
            actual = _context_get(context, path)
            ok = _eval_condition(actual, op, expected)
            all_ok = all_ok and ok
            evidence.append(
                f"{path} {op} {expected!r} (actual={actual!r}) -> {'pass' if ok else 'fail'}"
            )

        results.append(
            PolicyCheckResult(
                policy_id=policy_id,
                title=title,
                severity=severity,
                status="pass" if all_ok else "fail",
                rationale=rationale_pass if all_ok else rationale_fail,
                evidence=evidence,
            )
        )
    return results


def evaluate_policy_checks(
    assessment: RiskAssessment,
    questionnaire: dict[str, dict[str, str]] | None = None,
    *,
    policy_pack_path: str = "",
    include_default: bool = True,
) -> list[PolicyCheckResult]:
    """Run built-in and optional custom policy-as-code checks."""
    questionnaire = questionnaire or {}
    results: list[PolicyCheckResult] = []
    if include_default:
        results.extend(_default_policy_checks(assessment, questionnaire))

    if not policy_pack_path.strip():
        return results

    pack = load_policy_pack(policy_pack_path.strip())
    rules = [item for item in pack.get("rules", []) if isinstance(item, dict)]
    signal_ids = [signal.signal_id for signal in assessment.matched_signals]
    context: dict[str, Any] = {
        "assessment": {
            "overall_score": assessment.overall_score,
            "risk_level": assessment.risk_level,
            "residual_risk": assessment.residual_risk,
            "confidence": assessment.confidence,
            "applicable_standards": assessment.applicable_standards,
        },
        "questionnaire": questionnaire,
        "signals": signal_ids,
        "frameworks": assessment.applicable_standards,
    }
    results.extend(_evaluate_pack_rules(rules, context))
    return results


def policy_gate_status(results: list[PolicyCheckResult]) -> str:
    """Return pass/fail gate state from policy check results."""
    if any(result.status == "fail" and result.severity.lower() == "high" for result in results):
        return "fail"
    return "pass"


def build_integration_hook_payload(
    event_type: str,
    assessment: RiskAssessment,
    policy_results: list[PolicyCheckResult],
) -> dict[str, Any]:
    """Build outbound payload for CI/CD or governance integrations."""
    return {
        "event_type": event_type,
        "created_at": _now_utc(),
        "assessment": {
            "overall_score": assessment.overall_score,
            "risk_level": assessment.risk_level,
            "residual_risk": assessment.residual_risk,
            "confidence": assessment.confidence,
            "top_risks": assessment.top_risks[:3],
        },
        "policy": {
            "gate_status": policy_gate_status(policy_results),
            "checks": [asdict(item) for item in policy_results],
        },
    }


def write_hook_payload(output_path: str, payload: dict[str, Any]) -> str:
    """Persist integration payload (JSON) for downstream hooks."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return str(path)


def _trail_from_payload(payload: dict[str, Any]) -> GovernanceTrail:
    decisions_raw = payload.get("decisions", [])
    decisions: list[GovernanceDecision] = []
    if isinstance(decisions_raw, list):
        for item in decisions_raw:
            if not isinstance(item, dict):
                continue
            decisions.append(
                GovernanceDecision(
                    actor=str(item.get("actor", "")),
                    decision=str(item.get("decision", "")),
                    decided_at=str(item.get("decided_at", "")),
                    comment=str(item.get("comment", "")),
                )
            )

    approvers = payload.get("approvers", [])
    approver_list = [str(item) for item in approvers if isinstance(item, str)]

    return GovernanceTrail(
        trail_id=str(payload.get("trail_id", "")),
        created_at=str(payload.get("created_at", "")),
        status=str(payload.get("status", "pending")),
        requested_by=str(payload.get("requested_by", "")),
        approvers=approver_list,
        assessment_ref=str(payload.get("assessment_ref", "")),
        risk_level=str(payload.get("risk_level", "")),
        residual_risk=int(payload.get("residual_risk", 0)),
        policy_gate_status=str(payload.get("policy_gate_status", "unknown")),
        decisions=decisions,
    )


def load_governance_trails(path: str) -> list[GovernanceTrail]:
    """Load governance trails from JSONL storage."""
    file = Path(path)
    if not file.exists():
        return []

    trails: list[GovernanceTrail] = []
    try:
        lines = file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []

    for line in lines:
        clean = line.strip()
        if not clean:
            continue
        try:
            payload = json.loads(clean)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        trail = _trail_from_payload(payload)
        if trail.trail_id:
            trails.append(trail)
    return trails


def save_governance_trails(path: str, trails: list[GovernanceTrail]) -> str:
    """Persist governance trails to JSONL storage."""
    file = Path(path)
    file.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(json.dumps(asdict(item), ensure_ascii=False) for item in trails)
    file.write_text(content + ("\n" if content else ""), encoding="utf-8")
    return str(file)


def create_governance_trail(
    *,
    requested_by: str,
    approvers: list[str],
    assessment_ref: str,
    risk_level: str,
    residual_risk: int,
    policy_gate: str,
) -> GovernanceTrail:
    """Create a governance approval trail record."""
    now = _now_utc()
    seed = f"{assessment_ref}|{requested_by}|{now}|{residual_risk}"
    suffix = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:10]
    return GovernanceTrail(
        trail_id=f"gov_{suffix}",
        created_at=now,
        status="pending",
        requested_by=requested_by,
        approvers=sorted({item for item in approvers if item.strip()}),
        assessment_ref=assessment_ref,
        risk_level=risk_level,
        residual_risk=residual_risk,
        policy_gate_status=policy_gate,
        decisions=[],
    )


def record_governance_decision(
    trail: GovernanceTrail,
    *,
    actor: str,
    decision: str,
    comment: str = "",
) -> GovernanceTrail:
    """Append approval/rejection decision and update trail status."""
    if trail.status in {"approved", "rejected"}:
        raise ValueError(
            f"trail `{trail.trail_id}` is finalized with status `{trail.status}` and cannot be changed"
        )

    normalized = (decision or "").strip().lower()
    if normalized not in {"approve", "reject"}:
        raise ValueError("decision must be 'approve' or 'reject'")

    trail.decisions.append(
        GovernanceDecision(
            actor=actor,
            decision=normalized,
            decided_at=_now_utc(),
            comment=comment,
        )
    )
    if normalized == "reject":
        trail.status = "rejected"
        return trail

    approved_actors = {item.actor for item in trail.decisions if item.decision == "approve"}
    required = set(trail.approvers)
    if required and required.issubset(approved_actors):
        trail.status = "approved"
    else:
        trail.status = "pending"
    return trail
