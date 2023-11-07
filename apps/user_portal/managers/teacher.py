import bcrypt
from django.contrib.auth.base_user import BaseUserManager
from django.db import transaction
from django.utils import timezone
from hashid_field import Hashid
import secrets

from apps.user_portal.models.salted_password import SaltedPasswordModel


class TeacherManager(BaseUserManager):
    def create_user(self, email, password, **extra_fields):
        from apps.user_portal.models import GenericUser

        if not email:
            raise ValueError('Users must have an email address')
        teacher = self.model(
            email=TeacherManager.normalize_email(email),
            user_id=extra_fields["user_id"],
            user_name=extra_fields["user_name"],
        )
        teacher.special_key = teacher.generate_special_key()

        salt = bcrypt.gensalt()
        hashed_special_key = bcrypt.hashpw(teacher.special_key, salt)
        salted_password = SaltedPasswordModel(hashed_special_key=hashed_special_key)
        salted_password.set_password(password=password)

        # now = timezone.now()
        user = GenericUser(email=email, is_superuser=False)

        with transaction.atomic():
            salted_password.save()
            user.save(using=self._db)
            teacher.save()
        return user, salted_password

    # def create_superuser(self, email, password, **extra_fields):
    #     extra_fields.setdefault("is_staff", True)
    #     extra_fields.setdefault("is_superuser", True)
    #     extra_fields.setdefault("is_active", True)
    #     return self.create_user(email=email,
    #                             password=password,
    #                             **extra_fields)
