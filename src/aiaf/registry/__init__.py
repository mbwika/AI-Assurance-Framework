"""Model Registry Security module.

Provides ModelRecord, source tracking, checksum calculation and verification,
provenance scoring, MBOM generation, and simple persistence hooks.
"""

from .advisories import normalize_advisory
from .advisory_feed import create_advisory_feed, verify_advisory_feed
from .advisory_feed_v2 import (
    ADVISORY_FEED_V2_SCHEMA_VERSION,
    create_advisory_feed_v2,
    verify_advisory_feed_v2,
)
from .advisory_matcher_v2 import (
    ADVISORY_MATCHER_SCORING_VERSION,
    match_dependency_advisories_v2,
)
from .agent_registry import (
    CAPABILITY_FLAGS,
    CAPABILITY_RISK_RANK,
    AgentRegistryError,
    deregister_agent,
    get_agent,
    list_agents,
    register_agent,
    set_agent_status,
    set_tool_block,
)
from .agent_registry import (
    REGISTRY_VERSION as AGENT_REGISTRY_VERSION,
)
from .agent_registry import (
    STATUS_ACTIVE as AGENT_STATUS_ACTIVE,
)
from .agent_registry import (
    STATUS_DEREGISTERED as AGENT_STATUS_DEREGISTERED,
)
from .agent_registry import (
    STATUS_QUARANTINED as AGENT_STATUS_QUARANTINED,
)
from .agent_registry import (
    STATUS_SUSPENDED as AGENT_STATUS_SUSPENDED,
)
from .agent_registry import (
    TRUST_EXTERNAL as AGENT_TRUST_EXTERNAL,
)
from .agent_registry import (
    TRUST_INTERNAL as AGENT_TRUST_INTERNAL,
)
from .agent_registry import (
    TRUST_UNTRUSTED as AGENT_TRUST_UNTRUSTED,
)
from .agent_registry import (
    TRUST_USER as AGENT_TRUST_USER,
)
from .agent_registry import (
    TRUST_VERIFIED as AGENT_TRUST_VERIFIED,
)
from .agent_registry import (
    link_manifest as link_agent_manifest,
)
from .ai_threat_intel import (
    CATEGORY_AVAILABILITY,
    CATEGORY_DATA_ATTACKS,
    CATEGORY_EXFILTRATION,
    CATEGORY_IDENTITY_ATTACKS,
    CATEGORY_MODEL_INTEGRITY,
    CATEGORY_PROMPT_ATTACKS,
    CATEGORY_SUPPLY_CHAIN,
    SOURCE_CUSTOM,
    SOURCE_MITRE_ATLAS,
    SOURCE_OWASP_AGENTIC,
    SOURCE_OWASP_LLM,
    STIX_SPEC_VERSION,
    TAXII_CLIENT_VERSION,
    THREAT_INTEL_VERSION,
    ThreatIntelError,
    build_threat_landscape,
    correlate_agent,
    correlate_model,
    correlate_tool,
    export_stix_bundle,
    get_threat,
    ingest_threat,
    import_stix_bundle,
    list_threats,
    poll_taxii_collection,
    stix_attack_pattern_to_threat,
    threat_to_stix_attack_pattern,
)
from .ai_threat_intel import (
    SEVERITY_CRITICAL as THREAT_SEV_CRITICAL,
)
from .ai_threat_intel import (
    SEVERITY_HIGH as THREAT_SEV_HIGH,
)
from .ai_threat_intel import (
    SEVERITY_LOW as THREAT_SEV_LOW,
)
from .ai_threat_intel import (
    SEVERITY_MEDIUM as THREAT_SEV_MEDIUM,
)
from .artifact_integrity_v2 import (
    ARTIFACT_INTEGRITY_SCORING_VERSION,
    measure_artifact_integrity_v2,
    verify_artifact_integrity_v2,
)
from .attestation import create_provenance_attestation, verify_provenance_attestation
from .attestation_v2 import (
    PROVENANCE_ATTESTATION_SCHEMA_VERSION,
    create_provenance_attestation_v2,
    verify_provenance_attestation_v2,
)
from .checksum import calculate_sha256, verify_model
from .cyclonedx_bom import (
    CYCLONEDX_SPEC_VERSION,
    export_bom,
    import_bom,
)
from .dependency_discovery import discover_dependencies, merge_dependencies
from .dependency_discovery_v2 import (
    DEPENDENCY_DISCOVERY_SCORING_VERSION,
    discover_dependencies_v2,
)
from .deployment_verifier import (
    DEPLOYMENT_VERIFY_VERSION,
    DeploymentVerifyError,
    get_verify_result,
    list_verify_results,
    probe_endpoint,
    verify_deployment,
)
from .evidence_origin import (
    EVIDENCE_ORIGIN_VERSION,
    ORIGIN_TRUST_WEIGHT,
    EvidenceOrigin,
    FactLedger,
    coerce_origin,
    is_verified_grade,
    ledger_from_list,
    origin_trust_weight,
    tag_fact,
)
from .fact_reconciler import (
    DECIDABILITY_BOUNDS,
    RECONCILER_VERSION,
)
from .fact_reconciler import (
    reconcile as reconcile_facts,
)
from .hf_model_card import (
    HF_MODEL_CARD_VERSION,
    enrich_ledger,
    fetch_from_hub,
    parse_snapshot_dir,
    summarize_disclosure_posture,
)
from .identity_registry import (
    DELEGATION_ACTIVE,
    DELEGATION_EXPIRED,
    DELEGATION_REVOKED,
    IDENTITY_VERSION,
    PRINCIPAL_AGENT,
    PRINCIPAL_DATASET,
    PRINCIPAL_HUMAN,
    PRINCIPAL_MODEL,
    PRINCIPAL_SERVICE,
    PRINCIPAL_TOOL,
    PRINCIPAL_TYPES,
    IdentityError,
    get_authority_chain,
    get_delegation,
    get_principal,
    grant_delegation,
    list_delegations,
    list_principals,
    register_principal,
    revoke_delegation,
    update_principal,
    verify_authority,
)
from .identity_registry import (
    TRUST_EXTERNAL as IDENTITY_TRUST_EXTERNAL,
)
from .identity_registry import (
    TRUST_INTERNAL as IDENTITY_TRUST_INTERNAL,
)
from .identity_registry import (
    TRUST_LEVELS as IDENTITY_TRUST_LEVELS,
)
from .identity_registry import (
    TRUST_PRIVILEGED as IDENTITY_TRUST_PRIVILEGED,
)
from .identity_registry import (
    TRUST_UNTRUSTED as IDENTITY_TRUST_UNTRUSTED,
)
from .lineage_graph import (
    LINEAGE_VERSION,
    derive_lineage,
)
from .mbom import generate_mbom
from .mbom_v2 import AI_BOM_SPEC_VERSION, generate_ai_bom_v2, verify_ai_bom_v2
from .mcp_scanner import (
    SCAN_VERSION as MCP_SCAN_VERSION,
)
from .mcp_scanner import (
    STATUS_CHANGED as MCP_STATUS_CHANGED,
)
from .mcp_scanner import (
    STATUS_CLEAN as MCP_STATUS_CLEAN,
)
from .mcp_scanner import (
    STATUS_NO_TOOLS as MCP_STATUS_NO_TOOLS,
)
from .mcp_scanner import (
    STATUS_SUSPICIOUS as MCP_STATUS_SUSPICIOUS,
)
from .mcp_scanner import (
    STATUS_UNSAFE as MCP_STATUS_UNSAFE,
)
from .mcp_scanner import (
    scan_server_tools,
    scan_tool_descriptor,
)
from .models import ModelRecord
from .nhi_registry import (
    HYGIENE_AT_RISK,
    HYGIENE_CLEAN,
    HYGIENE_CRITICAL,
    HYGIENE_REVIEW_NEEDED,
    NHI_ACTIVE,
    NHI_AGENT_WORKER,
    NHI_DATA_CONNECTOR,
    NHI_DEPROVISIONING,
    NHI_DORMANT,
    NHI_GATEWAY,
    NHI_MODEL_SERVING,
    NHI_PENDING,
    NHI_PIPELINE_RUNNER,
    NHI_REVOKED,
    NHI_STATES,
    NHI_TOOL_EXECUTOR,
    NHI_TYPES,
    NHI_VERSION,
    NHIError,
    assess_nhi_hygiene,
    get_nhi,
    list_nhis,
    register_nhi,
    update_nhi,
    update_nhi_state,
)
from .provenance_v2 import (
    PROVENANCE_SCORING_VERSION,
    assess_provenance_v2,
    determine_provenance_risk,
)
from .rag_inventory import (
    ACCESS_CONTROL_MODES,
    TRUST_EXTERNAL,
    TRUST_INTERNAL,
    TRUST_LABELS,
    TRUST_RANK,
    TRUST_UNTRUSTED,
    TRUST_USER_GENERATED,
    TRUST_VERIFIED,
    RAGInventoryError,
    get_vector_store,
    list_vector_stores,
)
from .rag_inventory import (
    INVENTORY_VERSION as RAG_INVENTORY_VERSION,
)
from .rag_inventory import (
    get_document as get_rag_document,
)
from .rag_inventory import (
    list_documents as list_rag_documents,
)
from .rag_inventory import (
    register_document as register_rag_document,
)
from .rag_inventory import (
    register_store as register_rag_store,
)
from .serialization_scanner import (
    SCAN_VERSION as SERIALIZATION_SCAN_VERSION,
)
from .serialization_scanner import (
    STATUS_CLEAN,
    STATUS_ERROR,
    STATUS_NO_FILE,
    STATUS_UNSAFE,
    STATUS_UNSUPPORTED,
)
from .serialization_scanner import (
    scan_file as scan_model_artifact,
)
from .sigstore_verifier import (
    SIGSTORE_VERIFIER_VERSION,
    find_bundle,
)
from .sigstore_verifier import (
    verify_resolved_file as verify_sigstore,
)
from .skill_scanner import (
    RISK_CAPABILITY_MISMATCH,
    RISK_COVERT_CODE_EXECUTION,
    RISK_COVERT_NETWORK_ACCESS,
    RISK_INJECTION_PATTERN,
    RISK_OBFUSCATED_ENTRY_POINT,
    RISK_PERMISSION_SCOPE_CREEP,
    RISK_SUSPICIOUS_DEPENDENCY,
    RISK_UNSIGNED_PUBLISHER,
    SKILL_SCANNER_VERSION,
    scan_skill_manifest,
    scan_skill_registry,
)
from .skill_scanner import (
    RISK_CATEGORIES as SKILL_RISK_CATEGORIES,
)
from .skill_scanner import (
    STATUS_CLEAN as SKILL_STATUS_CLEAN,
)
from .skill_scanner import (
    STATUS_ERROR as SKILL_STATUS_ERROR,
)
from .skill_scanner import (
    STATUS_SUSPICIOUS as SKILL_STATUS_SUSPICIOUS,
)
from .skill_scanner import (
    STATUS_UNSAFE as SKILL_STATUS_UNSAFE,
)
from .tool_manifest import (
    MANIFEST_VERSION as TOOL_MANIFEST_VERSION,
)
from .tool_manifest import (
    ManifestError,
)
from .tool_manifest import (
    create_manifest as create_tool_manifest,
)
from .tool_manifest import (
    get_manifest as get_tool_manifest,
)
from .tool_manifest import (
    list_manifests as list_tool_manifests,
)
from .tool_manifest import (
    register_manifest as register_tool_manifest,
)
from .tool_manifest import (
    verify_manifest as verify_tool_manifest,
)
from .tracker import SourceTracker
from .weight_inspector import (
    INSPECTOR_VERSION as WEIGHT_INSPECTOR_VERSION,
)
from .weight_inspector import (
    STATUS_ERROR as WEIGHT_STATUS_ERROR,
)
from .weight_inspector import (
    STATUS_HEADER_ONLY as WEIGHT_STATUS_HEADER_ONLY,
)
from .weight_inspector import (
    STATUS_INSPECTED as WEIGHT_STATUS_INSPECTED,
)
from .weight_inspector import (
    STATUS_NO_FILE as WEIGHT_STATUS_NO_FILE,
)
from .weight_inspector import (
    STATUS_UNSUPPORTED as WEIGHT_STATUS_UNSUPPORTED,
)
from .weight_inspector import (
    inspect_file as inspect_model_weights,
)

__all__ = [
    "ModelRecord",
    "SourceTracker",
    "calculate_sha256",
    "verify_model",
    "EVIDENCE_ORIGIN_VERSION",
    "EvidenceOrigin",
    "FactLedger",
    "ORIGIN_TRUST_WEIGHT",
    "coerce_origin",
    "is_verified_grade",
    "ledger_from_list",
    "origin_trust_weight",
    "tag_fact",
    "PROVENANCE_SCORING_VERSION",
    "assess_provenance_v2",
    "determine_provenance_risk",
    "generate_mbom",
    "AI_BOM_SPEC_VERSION",
    "generate_ai_bom_v2",
    "verify_ai_bom_v2",
    "discover_dependencies",
    "merge_dependencies",
    "DEPENDENCY_DISCOVERY_SCORING_VERSION",
    "discover_dependencies_v2",
    "DEPLOYMENT_VERIFY_VERSION",
    "DeploymentVerifyError",
    "verify_deployment",
    "get_verify_result",
    "list_verify_results",
    "probe_endpoint",
    "ARTIFACT_INTEGRITY_SCORING_VERSION",
    "measure_artifact_integrity_v2",
    "verify_artifact_integrity_v2",
    "create_provenance_attestation",
    "verify_provenance_attestation",
    "PROVENANCE_ATTESTATION_SCHEMA_VERSION",
    "create_provenance_attestation_v2",
    "verify_provenance_attestation_v2",
    "normalize_advisory",
    "ADVISORY_MATCHER_SCORING_VERSION",
    "match_dependency_advisories_v2",
    "create_advisory_feed",
    "verify_advisory_feed",
    "ADVISORY_FEED_V2_SCHEMA_VERSION",
    "create_advisory_feed_v2",
    "verify_advisory_feed_v2",
    "SERIALIZATION_SCAN_VERSION",
    "STATUS_CLEAN",
    "STATUS_UNSAFE",
    "STATUS_NO_FILE",
    "STATUS_UNSUPPORTED",
    "STATUS_ERROR",
    "scan_model_artifact",
    # Phase 3 — HuggingFace model card
    "HF_MODEL_CARD_VERSION",
    "parse_snapshot_dir",
    "fetch_from_hub",
    "enrich_ledger",
    "summarize_disclosure_posture",
    # Phase 3 — Sigstore verifier
    "SIGSTORE_VERIFIER_VERSION",
    "verify_sigstore",
    "find_bundle",
    # Phase 3 — CycloneDX BOM
    "CYCLONEDX_SPEC_VERSION",
    "export_bom",
    "import_bom",
    # Phase 5 — Weight inspector
    "WEIGHT_INSPECTOR_VERSION",
    "WEIGHT_STATUS_INSPECTED",
    "WEIGHT_STATUS_NO_FILE",
    "WEIGHT_STATUS_UNSUPPORTED",
    "WEIGHT_STATUS_ERROR",
    "WEIGHT_STATUS_HEADER_ONLY",
    "inspect_model_weights",
    # Phase 5 — Lineage graph
    "LINEAGE_VERSION",
    "derive_lineage",
    # Phase 5 — Fact reconciler
    "RECONCILER_VERSION",
    "DECIDABILITY_BOUNDS",
    "reconcile_facts",
    # Phase 6 — MCP tool supply-chain scanner
    "MCP_SCAN_VERSION",
    "MCP_STATUS_CLEAN",
    "MCP_STATUS_SUSPICIOUS",
    "MCP_STATUS_UNSAFE",
    "MCP_STATUS_CHANGED",
    "MCP_STATUS_NO_TOOLS",
    "scan_tool_descriptor",
    "scan_server_tools",
    # Phase C — Agent registry
    "AGENT_REGISTRY_VERSION",
    "AgentRegistryError",
    "AGENT_STATUS_ACTIVE",
    "AGENT_STATUS_SUSPENDED",
    "AGENT_STATUS_QUARANTINED",
    "AGENT_STATUS_DEREGISTERED",
    "AGENT_TRUST_VERIFIED",
    "AGENT_TRUST_INTERNAL",
    "AGENT_TRUST_EXTERNAL",
    "AGENT_TRUST_USER",
    "AGENT_TRUST_UNTRUSTED",
    "CAPABILITY_FLAGS",
    "CAPABILITY_RISK_RANK",
    "register_agent",
    "get_agent",
    "list_agents",
    "deregister_agent",
    "set_agent_status",
    "set_tool_block",
    "link_agent_manifest",
    # Phase C — Signed tool manifests
    "TOOL_MANIFEST_VERSION",
    "ManifestError",
    "create_tool_manifest",
    "verify_tool_manifest",
    "register_tool_manifest",
    "get_tool_manifest",
    "list_tool_manifests",
    # Phase B — RAG vector-store inventory
    "RAG_INVENTORY_VERSION",
    "RAGInventoryError",
    "ACCESS_CONTROL_MODES",
    "TRUST_VERIFIED",
    "TRUST_INTERNAL",
    "TRUST_EXTERNAL",
    "TRUST_USER_GENERATED",
    "TRUST_UNTRUSTED",
    "TRUST_LABELS",
    "TRUST_RANK",
    "register_rag_store",
    "get_vector_store",
    "list_vector_stores",
    "register_rag_document",
    "get_rag_document",
    "list_rag_documents",
    # Feature 1 — AI-native threat intelligence engine
    "THREAT_INTEL_VERSION",
    "STIX_SPEC_VERSION",
    "TAXII_CLIENT_VERSION",
    "SOURCE_OWASP_LLM", "SOURCE_MITRE_ATLAS", "SOURCE_OWASP_AGENTIC", "SOURCE_CUSTOM",
    "THREAT_SEV_CRITICAL", "THREAT_SEV_HIGH", "THREAT_SEV_MEDIUM", "THREAT_SEV_LOW",
    "CATEGORY_PROMPT_ATTACKS", "CATEGORY_DATA_ATTACKS", "CATEGORY_SUPPLY_CHAIN",
    "CATEGORY_EXFILTRATION", "CATEGORY_AVAILABILITY", "CATEGORY_MODEL_INTEGRITY",
    "CATEGORY_IDENTITY_ATTACKS",
    "ThreatIntelError",
    "ingest_threat", "get_threat", "list_threats",
    "correlate_model", "correlate_agent", "correlate_tool",
    "build_threat_landscape",
    "threat_to_stix_attack_pattern", "stix_attack_pattern_to_threat",
    "export_stix_bundle", "import_stix_bundle", "poll_taxii_collection",
    # Feature F3 — Non-human identity (NHI) lifecycle governance
    "NHI_VERSION",
    "NHI_MODEL_SERVING", "NHI_AGENT_WORKER", "NHI_TOOL_EXECUTOR",
    "NHI_PIPELINE_RUNNER", "NHI_DATA_CONNECTOR", "NHI_GATEWAY",
    "NHI_TYPES",
    "NHI_PENDING", "NHI_ACTIVE", "NHI_DORMANT", "NHI_DEPROVISIONING", "NHI_REVOKED",
    "NHI_STATES",
    "HYGIENE_CLEAN", "HYGIENE_REVIEW_NEEDED", "HYGIENE_AT_RISK", "HYGIENE_CRITICAL",
    "NHIError",
    "register_nhi", "get_nhi", "list_nhis",
    "update_nhi_state", "update_nhi",
    "assess_nhi_hygiene",
    # Phase G — Skill / plugin supply-chain scanner
    "SKILL_SCANNER_VERSION",
    "SKILL_STATUS_CLEAN", "SKILL_STATUS_SUSPICIOUS", "SKILL_STATUS_UNSAFE", "SKILL_STATUS_ERROR",
    "RISK_PERMISSION_SCOPE_CREEP", "RISK_UNSIGNED_PUBLISHER",
    "RISK_SUSPICIOUS_DEPENDENCY", "RISK_OBFUSCATED_ENTRY_POINT",
    "RISK_COVERT_NETWORK_ACCESS", "RISK_COVERT_CODE_EXECUTION",
    "RISK_CAPABILITY_MISMATCH", "RISK_INJECTION_PATTERN",
    "SKILL_RISK_CATEGORIES",
    "scan_skill_manifest",
    "scan_skill_registry",
    # Feature 3 — Model/agent identity and delegation registry
    "IDENTITY_VERSION",
    "PRINCIPAL_MODEL", "PRINCIPAL_AGENT", "PRINCIPAL_TOOL",
    "PRINCIPAL_DATASET", "PRINCIPAL_HUMAN", "PRINCIPAL_SERVICE",
    "PRINCIPAL_TYPES",
    "IDENTITY_TRUST_UNTRUSTED", "IDENTITY_TRUST_EXTERNAL",
    "IDENTITY_TRUST_INTERNAL", "IDENTITY_TRUST_PRIVILEGED",
    "IDENTITY_TRUST_LEVELS",
    "DELEGATION_ACTIVE", "DELEGATION_REVOKED", "DELEGATION_EXPIRED",
    "IdentityError",
    "register_principal", "get_principal", "list_principals", "update_principal",
    "grant_delegation", "get_delegation", "revoke_delegation", "list_delegations",
    "verify_authority", "get_authority_chain",
]
