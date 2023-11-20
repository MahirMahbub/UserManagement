import secrets
from typing import NoReturn

import bcrypt
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import Permission
from django.db import transaction, DatabaseError, IntegrityError
from pydantic import EmailStr

from apps.user_portal.exceptions import SuperAdminCreationError
from apps.user_portal.models import SaltedPasswordModel
from apps.user_portal.protocols import DbCallableUser
from utils.custom_types import Params
from utils.inherit_types import ChildUser


class SuperAdminManager(BaseUserManager):
    def create_superuser(self, email: EmailStr, password: str | None = None,
                         **extra_fields: Params.kwargs) -> ChildUser | NoReturn:
        if not email:
            raise ValueError('Users must have an email address')
        email: str = SuperAdminManager.normalize_email(email)
        from apps.user_portal.models import SuperAdmin
        super_admin_user_object: ChildUser = SuperAdmin(
            email=email,
            **extra_fields
        )
        super_admin_user_object.special_key = super_admin_user_object.generate_special_key()
        try:
            salt: bytes = bcrypt.gensalt()
        except ValueError as val_err:
            raise SuperAdminCreationError("salt generation error") from val_err
        super_admin_user_object.salt = salt
        try:
            hashed_special_key: bytes = bcrypt.hashpw(super_admin_user_object.special_key, salt)
        except TypeError as type_err:
            raise SuperAdminCreationError("salt hashing error") from type_err
        try:
            salted_password_object: SaltedPasswordModel = SaltedPasswordModel(hashed_special_key=hashed_special_key)
        except (KeyError, ValueError, TypeError, IndexError) as salt_password_err:
            raise SuperAdminCreationError("password model creation error") from salt_password_err
        is_password_auto_generated: bool = False
        if password is None:
            is_password_auto_generated = True
            try:
                password: str = secrets.token_urlsafe(13)
            except (AssertionError, ValueError, TypeError, IndexError) as asser_err:
                raise SuperAdminCreationError("default password generation error") from asser_err
        salted_password_object.set_password(password=password)

        with transaction.atomic():
            super_admin_user_object.is_superuser = True
            try:
                salted_password_object.save(using=self._db)
                super_admin_user_object.save(using=self._db)
                super_admin_user_object.refresh_from_db()
            except (DatabaseError, IntegrityError) as save_err:
                raise SuperAdminCreationError("can not save user objects") from save_err
            if is_password_auto_generated:
                print("Your New Password is ", password)

            callable_user_object: DbCallableUser = super_admin_user_object.callableuser_ptr
            callable_user_object.is_superuser = True
            callable_user_object.is_staff = True

            required_permissions: list[Permission] = self.get_required_permissions()

            try:
                for permission in required_permissions:
                    callable_user_object.user_permissions.add(permission)

                callable_user_object.save(using=self._db)
            except (DatabaseError, IntegrityError,  TypeError) as add_permission_err:
                raise SuperAdminCreationError("can not add permission") from add_permission_err

        return super_admin_user_object

    def create_user(self, email: EmailStr, password: str, **extra_fields: Params.kwargs) -> ChildUser | NoReturn:
        self.create_superuser(email=email, password=password, extra_fields=extra_fields)

    @staticmethod
    def get_required_permissions() -> list[Permission]:
        return Permission.objects.all()
