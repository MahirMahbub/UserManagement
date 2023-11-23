from django.db import models

from apps.user_portal.managers.admin import AdminManager
from apps.user_portal.models import AbstractUser
from utils.db_mixins import BaseModelMixin, HelperMixin


class Admin(AbstractUser, BaseModelMixin, HelperMixin):
    """
    Admin is a special type of user that has access to the admin panel.
    The admin is created by or approved by the super admin.
    """

    is_active = models.BooleanField(default=True)
    password = None
    salt = models.BinaryField(max_length=255, null=True)
    special_key = models.BinaryField(max_length=255, unique=True)
    is_auto_password = models.BooleanField(default=False)
    last_login = None
    phone_number = models.CharField(max_length=10)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELD = USERNAME_FIELD

    objects = AdminManager()

    def __unicode__(self):
        return self.email
