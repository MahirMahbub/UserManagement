from django.db import models

from apps.user_portal.managers.teacher import TeacherManager
from apps.user_portal.models import AbstractUser
from utils.db_mixins import BaseModelMixin, HelperMixin


class Teacher(AbstractUser, BaseModelMixin, HelperMixin):
    """
    A Teacher is a user that can create and manage courses.
    """

    is_active = models.BooleanField(default=True)
    user_name = models.CharField(max_length=50, unique=True)
    user_id = models.CharField(max_length=50, unique=True)
    special_key = models.BinaryField(max_length=255, unique=True)
    password = None
    # last_login = None
    salt = models.BinaryField(max_length=255, null=True)
    phone_number = models.CharField(max_length=20, null=True)

    USERNAME_FIELD = 'user_name'
    REQUIRED_FIELD = 'email'

    objects = TeacherManager()

    def __unicode__(self):

        return self.email
