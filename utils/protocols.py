from typing import Protocol

from django.db.models import Manager
from rest_framework.authtoken.models import Token

from apps.user_portal.models import CallableUser


class RelatedManager(Protocol):

    def add(self, *args, **kwargs):
        pass


class DbCallableUser(Protocol):
    user_permissions: RelatedManager

    def save(self, *args, **kwargs):
        pass


class AutoUser(Protocol):
    email: str
    special_key: bytes
    salt: bytes
    is_auto_password: bool
    callableuser_ptr: CallableUser
    phone_number: str

    def save(self, *args, **kwargs):
        pass


class JwtRefreshTokenObject(Protocol):
    access_token: str


class AdminUser(Protocol):
    special_key: bytes
    salt: bytes
    is_auto_password: bool
    password: str
    callableuser_ptr: DbCallableUser
    jwt_refresh_token: JwtRefreshTokenObject

    def save(self, *args, **kwargs):
        pass

    def generate_special_key(self) -> bytes:
        pass


# class ChildUser(Protocol):
#     email: str
#     special_key: bytes
#     salt: bytes
#     phone_number: str
#     callableuser_ptr: DbCallableUser
#
#     def save(self, *args, **kwargs):
#         pass


class SequenceToken(Protocol):
    def __getitem__(self, item):
        pass

    def save(self, *args, **kwargs):
        pass

    @classmethod
    def generate_key(cls):
        pass
