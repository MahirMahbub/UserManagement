from rest_framework.permissions import BasePermission


class IsSuperAdmin(BasePermission):
    """
    Allows access only to super admins.
    """

    def has_permission(self, request, view) -> bool:
        if request.auth is None:
            return False
        return request.auth.payload.get("role") == "SuperAdmin"
