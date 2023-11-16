import secrets

import bcrypt
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import Permission
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from apps.user_portal.models import SaltedPasswordModel


class AdminManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        email = BaseUserManager.normalize_email(email)
        admin_user = self.model(
            email=email
        )
        admin_user.special_key = admin_user.generate_special_key()

        salt = bcrypt.gensalt()
        admin_user.salt = salt

        hashed_special_key = bcrypt.hashpw(admin_user.special_key, salt)
        salted_password = SaltedPasswordModel(hashed_special_key=hashed_special_key)
        if password is None:
            # salted_password.is_auto_password = True
            admin_user.is_auto_password = True
            password = secrets.token_urlsafe(13)
        salted_password.set_password(password=password)

        with transaction.atomic():
            salted_password.save(using=self._db)
            admin_user.save(using=self._db)
            callable_user = admin_user.callableuser_ptr
            all_permission = self.get_required_permissions()
            # callable_user.email = email
            for permission in all_permission:
                callable_user.user_permissions.add(permission)
            # callable_user.save(using=self._db)
        admin_user.password = password
        return admin_user

    @staticmethod
    def get_required_permissions():
        return [permission for permission in Permission.objects.exclude(Q(codename__endswith='callableuser') |
                                                                        Q(codename__endswith='logentry') |
                                                                        Q(codename__endswith='permission') |
                                                                        Q(codename__endswith='group') |
                                                                        Q(codename__endswith='session') |
                                                                        Q(codename__exact='change_saltedpasswordmodel') |
                                                                        Q(codename__exact='delete_saltedpasswordmodel'))]
