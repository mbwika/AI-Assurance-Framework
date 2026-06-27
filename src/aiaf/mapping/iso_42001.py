"""ISO/IEC 42001:2023 AI Management System (AIMS) standard mappings.

Provides clause-level mappings between AIAF controls and ISO 42001 requirements,
enabling organizations to use AIAF continuous assurance evidence as input to
their ISO 42001 certification or conformity assessment activities.

Reference: ISO/IEC 42001:2023 — Information technology — Artificial intelligence
           — Management system.
"""
from dataclasses import dataclass, field


@dataclass
class ISO42001Clause:
    clause_id: str
    title: str
    description: str
    aiaf_control_ids: list[str] = field(default_factory=list)
    evidence_examples: list[str] = field(default_factory=list)
    notes: str = ""


ISO_42001_CLAUSES: list[ISO42001Clause] = [
    ISO42001Clause(
        clause_id="4",
        title="Context of the organization",
        description=(
            "Understanding the organization and its context, needs and expectations of interested "
            "parties, and determining the scope of the AIMS."
        ),
        aiaf_control_ids=["AIAF-GOV-01", "AIAF-GOV-02"],
        evidence_examples=[
            "AI system inventory and classification",
            "Stakeholder register and requirements analysis",
            "AIMS scope document",
            "Internal and external issues register",
        ],
    ),
    ISO42001Clause(
        clause_id="5",
        title="Leadership",
        description=(
            "Top management commitment, establishing the AI policy, and assigning "
            "organizational roles, responsibilities, and authorities."
        ),
        aiaf_control_ids=["AIAF-GOV-01", "AIAF-HUMAN-01"],
        evidence_examples=[
            "AI policy signed by top management",
            "Management review records",
            "Roles and responsibilities matrix for AI governance",
        ],
    ),
    ISO42001Clause(
        clause_id="6",
        title="Planning",
        description=(
            "Actions to address risks and opportunities, AI objectives and planning "
            "to achieve them, and AI system impact assessment planning."
        ),
        aiaf_control_ids=["AIAF-RISK-01", "AIAF-RISK-02", "AIAF-BIAS-01"],
        evidence_examples=[
            "AI risk register with likelihood and impact ratings",
            "AI system impact assessment (AIAIA) records",
            "Objectives, targets, and improvement plans",
        ],
    ),
    ISO42001Clause(
        clause_id="7",
        title="Support",
        description=(
            "Resources, competence, awareness, communication, and management of documented information."
        ),
        aiaf_control_ids=["AIAF-GOV-02", "AIAF-MONITOR-01"],
        evidence_examples=[
            "Training and competence records for AI practitioners",
            "Internal communication plans for AI governance",
            "Document control procedures",
        ],
    ),
    ISO42001Clause(
        clause_id="8",
        title="Operation",
        description=(
            "Operational planning and control, AI system lifecycle (design, development, testing, "
            "deployment, monitoring, decommissioning), supply chain due diligence, and data management."
        ),
        aiaf_control_ids=["AIAF-SUPPLY-01", "AIAF-REG-01", "AIAF-DATA-01"],
        evidence_examples=[
            "AI system development lifecycle records",
            "Supply chain due diligence assessments",
            "Data governance policies and data quality reports",
            "AI Bill of Materials (AI-BOM) artifacts",
        ],
    ),
    ISO42001Clause(
        clause_id="9",
        title="Performance evaluation",
        description=(
            "Monitoring, measurement, analysis, and evaluation; internal audit; and management review."
        ),
        aiaf_control_ids=["AIAF-MONITOR-01", "AIAF-RISK-01"],
        evidence_examples=[
            "Continuous monitoring reports and alert logs",
            "Internal audit reports for AI systems",
            "Management review meeting minutes",
            "AI trustworthiness score trends",
        ],
    ),
    ISO42001Clause(
        clause_id="10",
        title="Improvement",
        description=(
            "Nonconformity and corrective action, and continual improvement of the AIMS."
        ),
        aiaf_control_ids=["AIAF-RISK-02"],
        evidence_examples=[
            "Corrective action records for AI incidents",
            "Continual improvement plans",
            "Post-incident review reports",
            "Risk re-evaluation records after remediation",
        ],
    ),
    ISO42001Clause(
        clause_id="A.2",
        title="Policies related to AI (Annex A)",
        description="Organizational policies governing responsible AI use, development, and deployment.",
        aiaf_control_ids=["AIAF-GOV-01", "AIAF-GOV-02"],
        evidence_examples=["Responsible AI policy", "Acceptable use policy for AI systems"],
        notes="Annex A control — normative only when selected in the Statement of Applicability.",
    ),
    ISO42001Clause(
        clause_id="A.3",
        title="Internal organization (Annex A)",
        description="Roles and responsibilities for AI governance within the organization.",
        aiaf_control_ids=["AIAF-HUMAN-01"],
        evidence_examples=["AI governance board charter", "RACI matrix for AI lifecycle roles"],
        notes="Annex A control.",
    ),
    ISO42001Clause(
        clause_id="A.6",
        title="AI system impact assessment (Annex A)",
        description="Systematic assessment of potential impacts of AI systems on individuals and society.",
        aiaf_control_ids=["AIAF-RISK-01", "AIAF-BIAS-01"],
        evidence_examples=["AI system impact assessments", "Bias and fairness audit reports"],
        notes="Annex A control — maps closely to EU AI Act conformity assessment requirements.",
    ),
    ISO42001Clause(
        clause_id="A.9",
        title="Human oversight of AI systems (Annex A)",
        description="Mechanisms enabling human review, correction, and shutdown of AI system operations.",
        aiaf_control_ids=["AIAF-HUMAN-01"],
        evidence_examples=["Human oversight logs", "Escalation procedures", "Kill-switch documentation"],
        notes="Annex A control.",
    ),
]


def map_aiaf_controls_to_iso42001(aiaf_control_id: str) -> list[ISO42001Clause]:
    """Return clauses that reference the given AIAF control ID."""
    return [c for c in ISO_42001_CLAUSES if aiaf_control_id in c.aiaf_control_ids]


def get_clause(clause_id: str) -> ISO42001Clause | None:
    """Look up a clause by its ID string."""
    return next((c for c in ISO_42001_CLAUSES if c.clause_id == clause_id), None)


def get_all_clauses() -> list[ISO42001Clause]:
    return list(ISO_42001_CLAUSES)
