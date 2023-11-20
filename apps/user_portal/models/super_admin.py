import bcrypt
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.db import models

from apps.user_portal.managers.super_admin import SuperAdminManager
from apps.user_portal.managers.teacher import TeacherManager
from apps.user_portal.models import AbstractUser
from utils.db_mixins import BaseModelMixin


class SuperAdmin(AbstractUser, BaseModelMixin):
    # email = models.EmailField(unique=True)
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

    def generate_special_key(self):
        salt = bcrypt.gensalt()
        return (bcrypt.hashpw
                (self.email.encode('utf-8'), salt))