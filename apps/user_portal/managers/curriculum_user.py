import secrets
from typing import NoReturn
import bcrypt
from django.contrib.auth.base_user import BaseUserManager
from pydantic import EmailStr
from apps.user_portal.exceptions import AdminCreationError, UserCreationError
from apps.user_portal.models.salted_password import SaltedPasswordModel
from apps.user_portal.permissions.base_permissions import BasePermissions
from utils.inherit_types import ChildUser
from utils.permission_mixins import PermissionMixin
from django.db import transaction, DatabaseError, IntegrityError

from utils.protocols import DbCallableUser


class CurriculumUserManager(BaseUserManager, PermissionMixin):
    permissions = BasePermissions()

    def create_user(
        self, email: EmailStr, password: str | None, **extra_fields
    ) -> ChildUser | NoReturn:
        if not email:
            raise ValueError("Users must have an email address")
        email: str = CurriculumUserManager.normalize_email(email)

        user_object: ChildUser = self.model(email=email, **extra_fields)

        user_object.special_key = user_object.generate_special_key()

        try:
            salt: bytes = bcrypt.gensalt()
        except ValueError as val_err:
            raise AdminCreationError("Salt generation error") from val_err
        user_object.salt = salt

        try:
            hashed_special_key: bytes = bcrypt.hashpw(user_object.special_key, salt)
        except TypeError as type_err:
            raise AdminCreationError("Salt hashing error") from type_err

        try:
            salted_password_object: SaltedPasswordModel = SaltedPasswordModel(
                hashed_special_key=hashed_special_key
            )
        except (KeyError, ValueError, TypeError, IndexError) as salt_password_err:
            raise AdminCreationError(
                "Password model creation error"
            ) from salt_password_err

        if password is None:
            user_object.is_auto_password = True
            try:
                password: str = secrets.token_urlsafe(13)
            except (AssertionError, ValueError, TypeError, IndexError) as asser_err:
                raise AdminCreationError(
                    "Default password generation error"
                ) from asser_err

        try:
            salted_password_object.set_password(password=password)
        except (ValueError, TypeError) as set_pass_err:
            raise AdminCreationError("Password set up error") from set_pass_err

        with transaction.atomic():
            try:
                salted_password_object.save(using=self._db)
                user_object.save(using=self._db)
                user_object.refresh_from_db()
            except (DatabaseError, IntegrityError) as save_err:
                raise AdminCreationError("Can not save user objects") from save_err

            callable_user_object: DbCallableUser = user_object.callableuser_ptr
            callable_user_object.is_superuser = False
            callable_user_object.is_staff = True

            required_permissions = self.permissions.get_permissions()

            try:
                user_object.user_permissions.set(
                    required_permissions if required_permissions else []
                )
                user_object.save()

            except (DatabaseError, IntegrityError) as add_permission_err:
                raise UserCreationError(
                    "Can not create permission"
                ) from add_permission_err
        user_object.password = password

        return user_object
