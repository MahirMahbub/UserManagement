from typing import Any

import bcrypt
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import update_last_login
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, PasswordField
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.user_portal.models import CallableUser, SaltedPasswordModel


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):  # noqa
    # def __init__(self, *args, **kwargs) -> None:
    #     # super().__init__(*args, **kwargs)
    #
    #     self.fields[self.username_field] = serializers.CharField(write_only=True)
    #     self.fields["password"] = PasswordField()
    # token_class = RefreshToken

    def validate(self, attrs: dict[str, Any]) -> dict[str, str]:
        # data = super().validate(attrs)
        # data={}
        authenticate_kwargs = {
            self.username_field: attrs[self.username_field],
            "password": attrs["password"],
        }
        try:
            authenticate_kwargs["request"] = self.context["request"]
        except KeyError:
            pass
        data = self.authenticate(authenticate_kwargs)

        return data

    def authenticate(self, attrs):
        data = {}
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

        refresh = self.get_token(self.user)
        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)
        if api_settings.UPDATE_LAST_LOGIN:
            base_user = CallableUser.objects.filter(email=attrs['email']).first()
            update_last_login(None, base_user)
        return data

    # @staticmethod
    # def get_sub_user(email):
    #     return CallableUser.objects.get_subclass(email=email)

    def check_password(self, password):
        special_key = self.user.special_key
        if special_key is None:
            return False
        encoded_special_key = special_key
        hashed_special_key = bcrypt.hashpw(encoded_special_key, self.user.salt)
        password_obj = SaltedPasswordModel.objects.get(hashed_special_key=hashed_special_key)
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
