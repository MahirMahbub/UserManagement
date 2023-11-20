from typing import Type

from django.db.models import QuerySet
from rest_framework import viewsets, serializers

from apps.user_portal.models import Admin
from apps.user_portal.permissions.super_admin import IsSuperAdmin
from apps.user_portal.serializers.admin import CreateAdminBySuperAdminSerializer, CreateAdminSerializer


class CreateAdminBySuperAdminViewSet(viewsets.ModelViewSet):
    """
    This endpoint allows a super admin to create an admin
    """
    serializer_class: Type[serializers.Serializer] = CreateAdminBySuperAdminSerializer
    permission_classes: list[Type[IsSuperAdmin]] = [IsSuperAdmin]
    queryset: QuerySet[Admin] = Admin.objects.all()
    http_method_names: list[str] = ['post']


class CreateAdminViewSet(viewsets.ModelViewSet):
    """
    This endpoint allows to create an admin by himself. Equivalent to signup/register.
    To be activated, needs approval from super admin
    """
    serializer_class: Type[serializers.Serializer] = CreateAdminSerializer
    queryset: QuerySet[Admin] = Admin.objects.all()
    http_method_names: list[str] = ['post']
