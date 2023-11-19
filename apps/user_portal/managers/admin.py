import secrets
from typing import List

import bcrypt
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import Permission
from django.db import transaction
from django.db.models import Q

from apps.user_portal.models import SaltedPasswordModel
from apps.user_portal.protocols import AdminUser, DbCallableUser


class AdminManager(BaseUserManager):
    def create_user(self, email, password=None, is_active=True, **extra_fields):
        email: str = BaseUserManager.normalize_email(email)
        admin_user: AdminUser = self.model(
            email=email,
            phone_number=extra_fields.get('phone_number'),
            is_active=is_active
        )
        admin_user.special_key = admin_user.generate_special_key()

        salt: bytes = bcrypt.gensalt()
        admin_user.salt = salt

        hashed_special_key: bytes = bcrypt.hashpw(admin_user.special_key, salt)
        salted_password: SaltedPasswordModel = SaltedPasswordModel(hashed_special_key=hashed_special_key)
        if password is None:
            admin_user.is_auto_password = True
            password: str = secrets.token_urlsafe(13)
        salted_password.set_password(password=password)

        with transaction.atomic():
            salted_password.save(using=self._db)
            admin_user.save(using=self._db)
            callable_user_relation: DbCallableUser = admin_user.callableuser_ptr
            all_permission: list[Permission] = self.get_required_permissions()
            for permission in all_permission:
                callable_user_relation.user_permissions.add(permission)
        admin_user.password = password
        return admin_user

    @staticmethod
    def get_required_permissions() -> list[Permission]:
        return [permission for permission in Permission.objects.exclude(Q(codename__endswith='callableuser') |
                                                                        Q(codename__endswith='logentry') |
                                                                        Q(codename__endswith='permission') |
                                                                        Q(codename__endswith='group') |
                                                                        Q(codename__endswith='session') |
                                                                        Q(codename__exact='change_saltedpasswordmodel') |
                                                                        Q(codename__exact='delete_saltedpasswordmodel'))]
