from rest_framework.permissions import BasePermission


class IsSuperAdmin(BasePermission):
    """
    Allows access only to super admins.
    """

    def has_permission(self, request, view) -> bool:
        return request.auth.payload.get("role") == "SuperAdmin"
