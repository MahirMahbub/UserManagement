from apps.user_portal.serializers.teacher import (
    CreateTeacherSerializer,
    CreateTeacherByAdminSerializer,
)
from apps.user_portal.permissions.super_admin import IsSuperAdmin
from apps.user_portal.views.user import CreateUserByAdminViewSet, CreateUserViewSet


class CreateTeacherViewSet(CreateUserViewSet):
    serializer_class = CreateTeacherSerializer


class CreateTeacherByAdminViewSet(CreateUserByAdminViewSet):
    serializer_class = CreateTeacherByAdminSerializer
    permission_classes = [IsSuperAdmin]
