"""Authentication and authorization for the AI Assurance Framework."""
from .api_key import verify_api_key, APIKeyDependency
from .rbac import Permission, Role, ROLE_PERMISSIONS, require_permission

__all__ = [
    "verify_api_key",
    "APIKeyDependency",
    "Permission",
    "Role",
    "ROLE_PERMISSIONS",
    "require_permission",
]
