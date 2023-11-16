from typing import Protocol


class AutoUser(Protocol):
    special_key: bytes
    salt: bytes
    is_auto_password: bool

    def save(self, *args, **kwargs):
        pass


class JwtRefreshTokenObject(Protocol):
    access_token: str
