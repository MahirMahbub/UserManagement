import bcrypt
from django.contrib.auth.base_user import BaseUserManager
from django.db import transaction, DatabaseError, IntegrityError
from pydantic import EmailStr

from apps.user_portal.exceptions import TeacherCreationError
from apps.user_portal.models.salted_password import SaltedPasswordModel
from apps.user_portal.protocols import DbCallableUser
from utils.custom_types import Params
from utils.inherit_types import ChildUser


class TeacherManager(BaseUserManager):
    def create_user(self, email: EmailStr, password: str | None = None, **extra_fields: Params.kwargs) -> ChildUser:
        if not email:
            raise ValueError('Users must have an email address')
        email: str = TeacherManager.normalize_email(email)
        teacher: ChildUser = self.model(
            email=email,
            user_id=extra_fields["user_id"],
            user_name=extra_fields["user_name"],
            **extra_fields
        )
        teacher.special_key = teacher.generate_special_key()
        try:
            salt: bytes = bcrypt.gensalt()
        except ValueError as val_err:
            raise TeacherCreationError("Salt generation error") from val_err
        teacher.salt = salt
        try:
            hashed_special_key: bytes = bcrypt.hashpw(teacher.special_key, salt)
        except TypeError as type_err:
            raise TeacherCreationError("Salt hashing error") from type_err
        try:
            salted_password: SaltedPasswordModel = SaltedPasswordModel(hashed_special_key=hashed_special_key)
        except (KeyError, ValueError, TypeError, IndexError) as salt_password_err:
            raise TeacherCreationError("Password model creation error") from salt_password_err
        try:
            salted_password.set_password(password=password)
        except (ValueError, TypeError) as set_pass_err:
            raise TeacherCreationError("Password set up error") from set_pass_err

        with transaction.atomic():

            try:
                salted_password.save(using=self._db)
                teacher.save(using=self._db)

                teacher.refresh_from_db()
                callable_user_relation: DbCallableUser = teacher.callableuser_ptr
                callable_user_relation.is_superuser = False
                callable_user_relation.is_staff = False

                callable_user_relation.save(using=self._db)
            except (DatabaseError, IntegrityError) as save_err:
                raise TeacherCreationError("Can not save user objects") from save_err
        teacher.password = password
        return teacher
