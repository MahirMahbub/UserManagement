import secrets
from typing import NoReturn

import bcrypt
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import Permission
from django.db import transaction, DatabaseError, IntegrityError
from pydantic import EmailStr

from apps.user_portal.exceptions import AdminCreationError
from apps.user_portal.models import SaltedPasswordModel
from utils.protocols import DbCallableUser
from utils.custom_types import Params
from utils.inherit_types import ChildUser
from utils.permission_mixins import PermissionMixin


class AdminManager(BaseUserManager, PermissionMixin):
    """
    Manager for all Admin Users.
    """
    def create_user(self, email: EmailStr, password: str | None = None,
                    **extra_fields: Params.kwargs) -> ChildUser | NoReturn:
        """
        Create and save an Admin User with the given email, password and other information.
        """

        if not email:
            raise ValueError('Users must have an email address')
        email: str = AdminManager.normalize_email(email)

        admin_user_object: ChildUser = self.model(
            email=email,
            # phone_number=extra_fields.get('phone_number'),
            **extra_fields
        )
        admin_user_object.special_key = admin_user_object.generate_special_key()

        try:
            salt: bytes = bcrypt.gensalt()
        except ValueError as val_err:
            raise AdminCreationError("Salt generation error") from val_err
        admin_user_object.salt = salt

        try:
            hashed_special_key: bytes = bcrypt.hashpw(admin_user_object.special_key, salt)
        except TypeError as type_err:
            raise AdminCreationError("Salt hashing error") from type_err

        try:
            salted_password_object: SaltedPasswordModel = SaltedPasswordModel(hashed_special_key=hashed_special_key)
        except (KeyError, ValueError, TypeError, IndexError) as salt_password_err:
            raise AdminCreationError("Password model creation error") from salt_password_err

        if password is None:
            admin_user_object.is_auto_password = True
            try:
                password: str = secrets.token_urlsafe(13)
            except (AssertionError, ValueError, TypeError, IndexError) as asser_err:
                raise AdminCreationError("Default password generation error") from asser_err

        try:
            salted_password_object.set_password(password=password)
        except (ValueError, TypeError) as set_pass_err:
            raise AdminCreationError("Password set up error") from set_pass_err

        with transaction.atomic():
            try:
                salted_password_object.save(using=self._db)
                admin_user_object.save(using=self._db)
                admin_user_object.refresh_from_db()
            except (DatabaseError, IntegrityError) as save_err:
                raise AdminCreationError("Can not save user objects") from save_err

            callable_user_object: DbCallableUser = admin_user_object.callableuser_ptr
            callable_user_object.is_superuser = False
            callable_user_object.is_staff = True

            required_permissions: list[Permission] = self.get_required_permissions_for_admin()

            try:
                for permission in required_permissions:
                    callable_user_object.user_permissions.add(permission)

                callable_user_object.save(using=self._db)

            except (DatabaseError, IntegrityError, TypeError) as add_permission_err:
                raise AdminCreationError("Can not create permission") from add_permission_err

        admin_user_object.password = password

        return admin_user_object
