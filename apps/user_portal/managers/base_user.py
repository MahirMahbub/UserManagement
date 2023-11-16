import secrets

import bcrypt
from django.contrib.auth.base_user import BaseUserManager as DjBaseUserManager
from django.db import transaction
from django.utils import timezone
from model_utils.managers import InheritanceManager

from apps.user_portal.models import SaltedPasswordModel



class BaseUserManager(DjBaseUserManager, InheritanceManager):
    """
    Manager for all Users types
    create_user() and create_superuser() must be overriden as we do not use
    unique username but unique email.
    """

    # def create_user_(self, email=None, password=None, **extra_fields):
    #     from apps.user_portal.models import GenericUser
    #     now = timezone.now()
    #     email = BaseUserManager.normalize_email(email)
    #     u = GenericUser(email=email, is_superuser=False, **extra_fields)
    #     u.save(using=self._db)
    #     return u

    # def create_teacher(self, email=None, password=None, **extra_fields):
    #     now = timezone.now()
    #     email = BaseUserManager.normalize_email(email)
    #     u = Teacher(email=email, is_superuser=False, last_login=now,
    #                 **extra_fields)
    #     u.set_password(password)
    #     u.save(using=self._db)
    #     return u

    # def create_student(self, email, password, **extra_fields):
    #     u = self.create_user_(email, password, **extra_fields)
    #     u.is_superuser = True
    #     u.save(using=self._db)
    #     return u

    def create_superuser(self, email=None, password=secrets.token_urlsafe(13), **extra_fields):
        now = timezone.now()
        email = BaseUserManager.normalize_email(email)

        special_key_salt = bcrypt.gensalt()
        special_key = bcrypt.hashpw(email.encode('utf-8'), special_key_salt)

        special_key_hash_salt = bcrypt.gensalt()
        hashed_special_key = bcrypt.hashpw(special_key, special_key_hash_salt)
        salted_password = SaltedPasswordModel(hashed_special_key=hashed_special_key)
        salted_password.set_password(password=password)


        from apps.user_portal.models.super_admin import SuperAdmin
        admin_user = SuperAdmin(email=email, special_key=special_key, salt=special_key_hash_salt)

        with transaction.atomic():
            salted_password.save(using=self._db)
            admin_user.save(using=self._db)
            print("Your New Password is ", password)
        return admin_user
