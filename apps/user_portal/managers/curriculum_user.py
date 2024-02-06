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


class CurriculumUserManager(BaseUserManager):
    permissions = BasePermissions()

    def create_user(
        self, email: EmailStr, password: str | None = None, **extra_fields
    ) -> ChildUser | NoReturn:
        if not email:
            raise ValueError("Users must have an email address")
        email: str = CurriculumUserManager.normalize_email(email)

        user_object: ChildUser = self.model(email=email, **extra_fields)
        user_object.special_key = user_object.generate_special_key()

        salt: bytes = bcrypt.gensalt()
        user_object.salt = salt
        hashed_special_key: bytes = bcrypt.hashpw(user_object.special_key, salt)
        salted_password_object: SaltedPasswordModel = SaltedPasswordModel(
            hashed_special_key=hashed_special_key
        )

        if password is None:
            user_object.is_auto_password = True
            password: str = secrets.token_urlsafe(13)

        salted_password_object.set_password(password=password)

        with transaction.atomic():
            salted_password_object.save(using=self._db)
            user_object.save(using=self._db)
            user_object.refresh_from_db()

            callable_user_object: DbCallableUser = user_object.callableuser_ptr
            callable_user_object.is_superuser = False
            callable_user_object.is_staff = True

            required_permissions = self.permissions.get_permissions()
            user_object.user_permissions.set(required_permissions)
            user_object.save()

        user_object.password = password

        return user_object
