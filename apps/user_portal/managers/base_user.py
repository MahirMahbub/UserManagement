import secrets

import bcrypt
from django.contrib.auth.base_user import BaseUserManager as DjBaseUserManager
from django.contrib.auth.models import Permission
from django.db import transaction
from django.utils import timezone
from model_utils.managers import InheritanceManager

from apps.user_portal.managers.super_admin import SuperAdminManager
from apps.user_portal.models import SaltedPasswordModel


class BaseUserManager(DjBaseUserManager, InheritanceManager):
    """
    Manager for all Users types
    create_user() and create_superuser() must be overriden as we do not use
    unique username but unique email.
    """
    def create_superuser(self, email=None, password=None, **extra_fields):
        return SuperAdminManager().create_superuser(email=email, password=password, extra_fields=extra_fields)

    @staticmethod
    def get_required_permissions():
        return Permission.objects.all()
