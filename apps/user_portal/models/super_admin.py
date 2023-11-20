from django.db import models

from apps.user_portal.managers.super_admin import SuperAdminManager
from apps.user_portal.models import AbstractUser
from utils.db_mixins import BaseModelMixin, HelperMixin


class SuperAdmin(AbstractUser, BaseModelMixin, HelperMixin):
    """
    SuperAdmin is a special type of user that has access to the admin panel. The super admin
    is created by the system and has access to all the admin panels.
    """

    is_active = models.BooleanField(default=True)
    password = None
    salt = models.BinaryField(max_length=255, null=True)
    special_key = models.BinaryField(max_length=255, unique=True)
    is_auto_password = models.BooleanField(default=True)
    phone_number = models.CharField(max_length=20, null=True)
    last_login = None
    USERNAME_FIELD = 'email'
    REQUIRED_FIELD = USERNAME_FIELD

    objects = SuperAdminManager()

    def __unicode__(self):

        return self.email
