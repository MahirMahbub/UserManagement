from rest_framework.permissions import (
    BasePermission,
    SAFE_METHODS,
    IsAuthenticatedOrReadOnly,
)


class IsTeacher(BasePermission):
    def has_permission(self, request, view):
        if request.auth is None:
            return False
        return request.auth.payload.get("role") == "Teacher"


class IsTeacherOrReadOnly(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.method in SAFE_METHODS
            or request.auth
            and request.auth.payload.get("role") == "Teacher"
        )
