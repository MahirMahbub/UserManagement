from typing import NoReturn

import bcrypt
from django.db import models

from utils.db_mixins import BaseModelMixin


class SaltedPasswordModel(BaseModelMixin):
    """
    This model is used to store a salted password.
    """

    password = models.BinaryField(max_length=255)
    hashed_special_key = models.BinaryField(max_length=255, unique=True)
    is_enabled = models.BooleanField(default=True)

    def check_password(self, password: str) -> bool | NoReturn:
        """
        Returns True if the given password is correct, False otherwise.
        """

        raise NotImplementedError("SaltedPasswordModel.check_password() "
                                  "must be implemented in a subclass")

    def set_password(self, password) -> None:
        """
        Sets the user's password to the given raw string, taking care of the
        password hashing. Doesn't save the User object.
        """

        salt: bytes = bcrypt.gensalt()
        hashed_password: bytes = bcrypt.hashpw(password.encode('utf-8'), salt)
        self.password = hashed_password

