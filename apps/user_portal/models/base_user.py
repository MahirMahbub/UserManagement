from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.db import models

from apps.user_portal.managers.base_user import BaseUserManager


class CallableUser(AbstractBaseUser, PermissionsMixin):
    """
    The CallableUser class allows to get any type of user by calling
    CallableUser.objects.get_subclass(email="my@email.dom") or
    CallableUser.objects.filter(email__endswith="@email.dom").select_subclasses()
    """
    email = models.EmailField(unique=True)
    USERNAME_FIELD = 'email'
    password = None
    objects = BaseUserManager()


class AbstractUser(CallableUser):
    """
    Here are the fields that are shared among specific User subtypes.
    Making it abstract makes 1 email possible in each User subtype.
    """

    is_superuser = False
    objects = BaseUserManager()

    def __unicode__(self):
        return self.email

    # REQUIRED_FIELD = [USERNAME_FIELD, "password"]

    class Meta:
        abstract = True

#
# class GenericUser(AbstractUser, PermissionsMixin):
#     """
#     A GenericUser is any type of system user (such as an admin).
#     This is the one that should be referenced in settings.AUTH_USER_MODEL
#     """
#     is_superuser = models.BooleanField(default=False)
#     is_staff = models.BooleanField(default=True)
