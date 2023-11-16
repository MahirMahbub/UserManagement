import secrets

import bcrypt
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import Permission
from django.db import transaction

from apps.user_portal.models import SaltedPasswordModel


class SuperAdminManager(BaseUserManager):
    def create_superuser(self, email=None, password=None , **extra_fields):
        email = SuperAdminManager.normalize_email(email)
        from apps.user_portal.models import SuperAdmin
        admin_user = SuperAdmin(
            email=email
        )
        admin_user.special_key = admin_user.generate_special_key()

        salt = bcrypt.gensalt()
        admin_user.salt = salt

        hashed_special_key = bcrypt.hashpw(admin_user.special_key, salt)
        salted_password = SaltedPasswordModel(hashed_special_key=hashed_special_key)

        is_password_auto_generated = False
        if password is None:
            is_password_auto_generated = True
            password = secrets.token_urlsafe(13)
        salted_password.set_password(password=password)

        with transaction.atomic():
            salted_password.save(using=self._db)
            admin_user.is_superuser = True
            admin_user.save(using=self._db)
            if is_password_auto_generated:
                print("Your New Password is ", password)
            callable_user = admin_user.callableuser_ptr
            all_permission = self.get_required_permissions()
            # callable_user.email = email
            for permission in all_permission:
                callable_user.user_permissions.add(permission)
            # callable_user.save(using=self._db)
        return admin_user

    def create_user(self, email, password, **extra_fields):
        self.create_superuser(email=email, password=password, extra_fields=extra_fields)

    @staticmethod
    def get_required_permissions():
        return Permission.objects.all()
