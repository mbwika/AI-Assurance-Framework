"""Role-based access control for multi-operator AIAF deployments.

The current implementation provides the data model and permission lookup
helpers.  Full enforcement is wired in once OIDC / JWT integration is added;
until then, operator roles can be enforced programmatically via
``require_permission``.
"""
from enum import Enum


class Role(str, Enum):
    READER = "reader"
    ANALYST = "analyst"
    OPERATOR = "operator"
    ADMIN = "admin"


class Permission(str, Enum):
    # Registry
    READ_REGISTRY = "read:registry"
    WRITE_REGISTRY = "write:registry"
    # Risk
    READ_RISK = "read:risk"
    WRITE_RISK = "write:risk"
    # Governance
    READ_GOVERNANCE = "read:governance"
    WRITE_GOVERNANCE = "write:governance"
    REVIEW_EVIDENCE = "review:evidence"
    # Reporting
    READ_REPORTING = "read:reporting"
    WRITE_SNAPSHOTS = "write:snapshots"
    # Monitoring
    READ_MONITORING = "read:monitoring"
    ADMIN_MONITORING = "admin:monitoring"
    # Agent runtime
    READ_AGENTIC = "read:agentic"
    WRITE_AGENTIC = "write:agentic"
    # Administration
    ADMIN_ALL = "admin:all"


ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.READER: {
        Permission.READ_REGISTRY,
        Permission.READ_RISK,
        Permission.READ_GOVERNANCE,
        Permission.READ_REPORTING,
        Permission.READ_MONITORING,
        Permission.READ_AGENTIC,
    },
    Role.ANALYST: {
        Permission.READ_REGISTRY,
        Permission.READ_RISK,
        Permission.WRITE_RISK,
        Permission.READ_GOVERNANCE,
        Permission.WRITE_GOVERNANCE,
        Permission.READ_REPORTING,
        Permission.WRITE_SNAPSHOTS,
        Permission.READ_MONITORING,
        Permission.READ_AGENTIC,
    },
    Role.OPERATOR: {
        Permission.READ_REGISTRY,
        Permission.WRITE_REGISTRY,
        Permission.READ_RISK,
        Permission.WRITE_RISK,
        Permission.READ_GOVERNANCE,
        Permission.WRITE_GOVERNANCE,
        Permission.REVIEW_EVIDENCE,
        Permission.READ_REPORTING,
        Permission.WRITE_SNAPSHOTS,
        Permission.READ_MONITORING,
        Permission.ADMIN_MONITORING,
        Permission.READ_AGENTIC,
        Permission.WRITE_AGENTIC,
    },
    Role.ADMIN: set(Permission),
}


def require_permission(role: Role, permission: Permission) -> bool:
    """Return True if the given role holds the requested permission."""
    return permission in ROLE_PERMISSIONS.get(role, set())
