from django.contrib.auth.base_user import BaseUserManager as DjBaseUserManager
from model_utils.managers import InheritanceManager
from pydantic import EmailStr

from apps.user_portal.managers.super_admin import SuperAdminManager
from utils.custom_types import Params
from utils.inherit_types import ChildUser
from utils.permission_mixins import PermissionMixin


class BaseUserManager(DjBaseUserManager, InheritanceManager, PermissionMixin):
    """
    Manager for all Users types
    create_user() and create_superuser() must be overriden as we do not use
    unique username but unique email.
    """
    @staticmethod
    def create_superuser(email: EmailStr, password: str | None = None,
                         **extra_fields: Params.kwargs) -> ChildUser:
        """
        Create and save a SuperAdmin with the given email, password and other information.
        """

        return SuperAdminManager().create_superuser(email=email, password=password, extra_fields=extra_fields)


