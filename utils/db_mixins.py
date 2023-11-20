import bcrypt
from django.db import models
from django.db.models import DateTimeField


class TimeStampModelMixin(models.Model):
    created_at: DateTimeField = models.DateTimeField(auto_now_add=True)
    updated_at: DateTimeField = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class BaseModelMixin(TimeStampModelMixin):
    class Meta:
        abstract = True


class HelperMixin(object):
    def generate_special_key(self) -> bytes:
        """
        Generates a special key for the admin.
        """
        salt = bcrypt.gensalt()

        return bcrypt.hashpw(self.email.encode('utf-8'), salt)

    def generate_special_key_by_user_id(self) -> bytes:
        """
        Generates a special key for the teacher.
        """
        salt = bcrypt.gensalt()

        return bcrypt.hashpw(self.user_id.encode('utf-8'), salt)