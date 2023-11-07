import hashlib
import random

import bcrypt
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.db import models

from apps.user_portal.managers.teacher import TeacherManager


class Teacher(AbstractBaseUser):
    """
    A Teacher is a user that can create and manage courses.
    """
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    user_name = models.CharField(max_length=50, unique=True)
    user_id = models.CharField(max_length=50, unique=True)
    special_key = models.BinaryField(max_length=255, unique=True)
    password = None
    last_login = None
    salt = models.BinaryField(max_length=255, null=True)

    USERNAME_FIELD = 'user_name'
    REQUIRED_FIELD = 'email'

    objects = TeacherManager()

    def generate_special_key(self):
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(self.user_id.encode('utf-8'), salt)

    def __unicode__(self):
        return self.email
