from django.contrib.auth.base_user import BaseUserManager as DjBaseUserManager
from django.contrib.auth.models import Permission
from model_utils.managers import InheritanceManager
from pydantic import EmailStr

from apps.user_portal.managers.super_admin import SuperAdminManager
from utils.custom_types import Params
from utils.inherit_types import ChildUser


class BaseUserManager(DjBaseUserManager, InheritanceManager):
    """
    Manager for all Users types
    create_user() and create_superuser() must be overriden as we do not use
    unique username but unique email.
    """

    def create_superuser(self, email: EmailStr, password: str | None = None,
                         **extra_fields: Params.kwargs) -> ChildUser:
        return SuperAdminManager().create_superuser(email=email, password=password, extra_fields=extra_fields)

    @staticmethod
    def get_required_permissions() -> list[Permission]:
        return Permission.objects.all()
