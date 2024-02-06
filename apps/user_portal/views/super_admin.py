from typing import Type

from django.db.models import QuerySet
from rest_framework import viewsets, serializers
from rest_framework.viewsets import GenericViewSet
from rest_framework.mixins import CreateModelMixin
from apps.user_portal.models import Admin
from apps.user_portal.permissions.super_admin import IsSuperAdmin
from apps.user_portal.serializers.admin import (
    CreateAdminBySuperAdminSerializer,
    CreateAdminSerializer,
)
from apps.user_portal.serializers.curriculum_user import CreateAdminSerializer
from apps.user_portal.views.user import CreateUserViewSet, CreateUserByAdminViewSet


class CreateAdminBySuperAdminViewSet(CreateUserByAdminViewSet):
    """
    This endpoint allows a super admin to create an admin
    """

    serializer_class: Type[serializers.Serializer] = CreateAdminBySuperAdminSerializer
    permission_classes: list[Type[IsSuperAdmin]] = [IsSuperAdmin]


class CreateAdminViewSet(CreateUserViewSet):
    """
    This endpoint allows to create an admin by himself. Equivalent to signup/register.
    To be activated, needs approval from super admin
    """

    serializer_class: Type[serializers.Serializer] = CreateAdminSerializer
    # queryset: QuerySet[Admin] = Admin.objects.all()
    # http_method_names: list[str] = ["post"]
