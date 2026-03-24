"""Structured models for deterministic and LLM-assisted risk assessments."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class RiskSignal:
    """A matched deterministic risk signal."""

    signal_id: str
    label: str
    category: str
    weight: int
    matched_phrases: list[str] = field(default_factory=list)
    why_it_matters: str = ""
    framework_refs: list["FrameworkReference"] = field(default_factory=list)


@dataclass
class FrameworkReference:
    """External control-framework reference for a detected signal."""

    framework: str
    control_id: str
    title: str = ""
    description: str = ""

    @property
    def control(self) -> str:
        """Backward-compatible combined control label."""
        if self.framework and self.control_id:
            return f"{self.framework} {self.control_id}"
        return self.control_id


@dataclass
class Recommendation:
    """A practical recommendation tied to a risk signal."""

    signal_id: str
    category: str
    recommendation: str
    first_action: str
    seven_day_action: str


@dataclass
class InvestmentPriority:
    """Grouped investment priority for roadmap planning."""

    bucket: str
    rationale: str
    related_signals: list[str] = field(default_factory=list)
    score_contribution: int = 0


@dataclass
class RequirementControl:
    """Normalized requirement control extracted from source repositories."""

    id: str
    category: str
    mapped_layer: str
    document_title: str
    document_version: str
    document_path: str
    control_text: str
    control_text_en: str
    keywords: list[str] = field(default_factory=list)
    compliance_tags: list[str] = field(default_factory=list)
    severity: str = "medium"
    risk_weight: float = 0.5
    retrieval_score: float = 0.0
    retrieval_rank: int = 0
    retrieval_reason: str = ""
    retrieval_breakdown: dict[str, float] = field(default_factory=dict)
    framework_refs: list["FrameworkReference"] = field(default_factory=list)


@dataclass
class RequirementRisk:
    """Explainable requirement-linked risk result."""

    id: str
    risk: str
    why: str
    source_document: str
    reference_control: str
    mapped_layer: str
    severity: str
    impact: str
    score: float
    compliance_tags: list[str] = field(default_factory=list)


@dataclass
class PolicyCheckResult:
    """Policy-as-code check outcome."""

    policy_id: str
    title: str
    severity: str
    status: str
    rationale: str = ""
    evidence: list[str] = field(default_factory=list)


@dataclass
class GovernanceDecision:
    """Single governance approval/rejection event."""

    actor: str
    decision: str
    decided_at: str
    comment: str = ""


@dataclass
class GovernanceTrail:
    """Approval workflow trail attached to an assessment."""

    trail_id: str
    created_at: str
    status: str
    requested_by: str
    approvers: list[str] = field(default_factory=list)
    assessment_ref: str = ""
    risk_level: str = ""
    residual_risk: int = 0
    policy_gate_status: str = "unknown"
    decisions: list[GovernanceDecision] = field(default_factory=list)


@dataclass
class RiskAssessment:
    """Combined deterministic findings and response structure."""

    company_input: str
    overall_score: int
    risk_level: str
    likelihood: float = 0.0
    impact: float = 0.0
    inherent_risk: int = 0
    residual_risk: int = 0
    control_reduction: float = 0.0
    confidence: float = 0.0
    matched_signals: list[RiskSignal] = field(default_factory=list)
    top_risks: list[str] = field(default_factory=list)
    control_gaps: list[str] = field(default_factory=list)
    recommendations: list[Recommendation] = field(default_factory=list)
    seven_day_plan: list[str] = field(default_factory=list)
    investment_priorities: list[InvestmentPriority] = field(default_factory=list)
    framework_references: dict[str, list[FrameworkReference]] = field(default_factory=dict)
    questionnaire: dict[str, dict[str, str]] = field(default_factory=dict)
    factor_snapshot: dict[str, object] = field(default_factory=dict)
    questionnaire_context: dict[str, dict[str, str]] = field(default_factory=dict)
    detected_security_domains: list[str] = field(default_factory=list)
    mapped_requirements: list[RequirementControl] = field(default_factory=list)
    identified_requirement_risks: list[RequirementRisk] = field(default_factory=list)
    applicable_standards: list[str] = field(default_factory=list)
    control_coverage_percent: float = 0.0
    requirements_calibration_enabled: bool = False
    mapped_controls_count: int = 0
    retrieved_controls_count: int = 0
    requirements_controls_total: int = 0
    runtime_category_layers: list[dict[str, object]] = field(default_factory=list)
    explainability_payload: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Serialize to a plain dict for prompt wiring and exports."""
        return asdict(self)
