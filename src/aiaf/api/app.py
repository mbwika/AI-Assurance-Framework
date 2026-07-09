from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from . import adoption_velocity as adoption_velocity_router
from . import agent_security as agent_security_module
from . import agent_topology as agent_topology_router
from . import agentic as agentic_router
from . import architecture as architecture_router
from . import assistant as assistant_router
from . import assurance as assurance_router
from . import context_provenance as context_provenance_router
from . import deployment_verify as deployment_verify_router
from . import egress as egress_router
from . import frontier_eval as frontier_eval_router
from . import governance as governance_router
from . import guardrail as guardrail_router
from . import human_oversight as human_oversight_router
from . import identity as identity_router
from . import intake as intake_router
from . import interop as interop_router
from . import ledger as ledger_router
from . import mcp as mcp_router
from . import memory_integrity as memory_integrity_router
from . import models as models_router
from . import monitoring as monitoring_router
from . import nhi as nhi_router
from . import ops as ops_router
from . import policy_enforcement as policy_enforcement_router
from . import portal as portal_router
from . import rag as rag_router
from . import reporting as reporting_router
from . import resources as resources_router
from . import risk as risk_router
from . import risk_register as risk_register_router
from . import sandbox_posture as sandbox_posture_router
from . import skill_scanner as skill_scanner_router
from . import supply_chain as supply_chain_router
from . import system_redteam as system_redteam_router
from . import telemetry as telemetry_router
from . import threat_intel as threat_intel_router

app = FastAPI(title="AI Assurance Framework API")
app.include_router(portal_router.router)
app.include_router(assistant_router.router)
app.include_router(agentic_router.router)
app.include_router(guardrail_router.router)
app.include_router(ledger_router.router)
app.include_router(mcp_router.router)
app.include_router(telemetry_router.router)
app.include_router(agent_security_module.agents_router)
app.include_router(agent_security_module.tools_router)
app.include_router(intake_router.router)
app.include_router(rag_router.router)
app.include_router(interop_router.router)
app.include_router(models_router.router)
app.include_router(monitoring_router.router)
app.include_router(risk_router.router)
app.include_router(risk_register_router.router)
app.include_router(supply_chain_router.router)
app.include_router(ops_router.router)
app.include_router(assurance_router.router)
app.include_router(threat_intel_router.router)
app.include_router(resources_router.router)
app.include_router(identity_router.router)
app.include_router(system_redteam_router.router)
app.include_router(memory_integrity_router.router)
app.include_router(agent_topology_router.router)
app.include_router(nhi_router.router)
app.include_router(policy_enforcement_router.router)
app.include_router(skill_scanner_router.router)
app.include_router(adoption_velocity_router.router)
app.include_router(sandbox_posture_router.router)
app.include_router(frontier_eval_router.router)
app.include_router(human_oversight_router.router)
app.include_router(governance_router.router)
app.include_router(reporting_router.router)
app.include_router(deployment_verify_router.router)
app.include_router(architecture_router.router)
app.include_router(egress_router.router)
app.include_router(context_provenance_router.router)

# Serve the compiled dashboard's static assets (JS/CSS) when a build exists.
if portal_router.ASSETS_DIR.is_dir():
    app.mount(
        "/assets",
        StaticFiles(directory=str(portal_router.ASSETS_DIR)),
        name="assets",
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/v1/info")
def info():
    return {"name": "AI Assurance Framework", "version": "0.2.0"}
