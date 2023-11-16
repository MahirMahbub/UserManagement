from typing import Any, List, Dict

import bcrypt
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import update_last_login
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, PasswordField
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken, Token

from apps.user_portal.models import CallableUser, SaltedPasswordModel
from apps.user_portal.protocols import JwtRefreshTokenObject


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user) -> Token:
        """
        Override this method to add custom claims
        """
        role: str = user.__class__.__name__
        scopes: list[dict[str, str]] = [
            {
                "codename": f"{permission.codename}",
                "name": f"{permission.name}",

            } for permission in user.user_permissions.all()
        ]
        token: Token = super().get_token(user)
        token['role'] = role
        token['scopes'] = scopes

        return token

    def validate(self, attrs: dict[str, Any]) -> dict[str, str]:
        """
        Validate the given credentials. Override this method to support
        """
        try:
            authenticate_kwargs: dict[str | Any, Any] = {
                self.username_field: attrs[self.username_field],
                "password": attrs["password"],
            }
        except KeyError:
            raise serializers.ValidationError({"message": "Invalid Credentials"})
        try:
            authenticate_kwargs["request"] = self.context["request"]
        except KeyError:
            pass
        data: dict[str, str] = self.authenticate(authenticate_kwargs)

        return data

    def authenticate(self, attrs: dict[str, Any]) -> dict[str, str]:
        """
        Authenticate the given credentials. Override this method to support
        """
        data: dict = {}
        try:
            self.user = CallableUser.objects.filter(email=attrs['email']).select_subclasses().first()
        except api_settings.AUTH_USER_MODEL.DoesNotExist:
            raise serializers.ValidationError({"message": "Invalid Email, User not found"})
        if self.user is None:
            raise serializers.ValidationError({"message": "Invalid Email, Machine not found"})

        # Get Password using Special Key's hash

        if not self.check_password(attrs["password"]):
            raise serializers.ValidationError({"message": "Invalid Password"})

        if not self.user_can_authenticate():
            raise serializers.ValidationError({"message": "User is not active"})

        refresh: JwtRefreshTokenObject | Token = self.get_token(self.user)
        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)
        if api_settings.UPDATE_LAST_LOGIN:
            base_user: CallableUser = CallableUser.objects.filter(email=attrs['email']).first()
            update_last_login(None, base_user)
        return data

    def check_password(self, password):
        """
        Returns a boolean of whether the password matches
        """
        try:
            special_key = self.user.special_key
        except AttributeError:
            return False
        if special_key is None:
            return False
        encoded_special_key = special_key
        try:
            hashed_special_key = bcrypt.hashpw(encoded_special_key, self.user.salt)
        except TypeError:
            return False
        except AttributeError:
            return False
        try:
            password_obj = SaltedPasswordModel.objects.get(hashed_special_key=hashed_special_key)
        except SaltedPasswordModel.DoesNotExist:
            return False
        if password_obj is not None:
            password_check = bcrypt.checkpw(password.encode('utf-8'), password_obj.password)
            if password_check:
                return True
            else:
                return False
        return False

    def user_can_authenticate(self):
        """
        Reject users with is_active=False. Custom user models that don't have
        that attribute are allowed.
        """
        email = getattr(self.user, "email", None)
        if email is None:
            return False
        return getattr(self.user, "is_active", False)
