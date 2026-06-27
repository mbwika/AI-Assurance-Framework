"""Authentication and authorization for the AI Assurance Framework."""
from .api_key import APIKeyDependency, verify_api_key
from .rbac import ROLE_PERMISSIONS, Permission, Role, require_permission

__all__ = [
    "verify_api_key",
    "APIKeyDependency",
    "Permission",
    "Role",
    "ROLE_PERMISSIONS",
    "require_permission",
]
