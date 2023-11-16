import secrets
from typing import OrderedDict, Any, Tuple

import bcrypt
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.db import transaction
from django.utils.encoding import smart_str
from django.utils.functional import Promise
from django.utils.http import urlsafe_base64_decode
from environ import Env
from rest_framework import serializers
from rest_framework.fields import EmailField, CharField

from apps.user_portal.exceptions import UrlSafeEncodeError, PasswordResetTokenGenerationError
from apps.user_portal.models import CallableUser, SaltedPasswordModel
from apps.user_portal.protocols import AutoUser
from utils.email import send_email, get_uid_and_token_for_reset


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email: EmailField = serializers.EmailField()

    def validate(self, attrs: OrderedDict) -> OrderedDict:
        email: str = attrs.get('email')
        if not email:
            raise serializers.ValidationError({"message": "Email is required"})
        user: CallableUser = CallableUser.objects.filter(email=email).first()
        if not user:
            raise serializers.ValidationError({"message": "Invalid Email"})
        try:
            token, uid = get_uid_and_token_for_reset(user)
        except UrlSafeEncodeError as ue:
            raise serializers.ValidationError({"message": "Error encoding the user id"})
        except PasswordResetTokenGenerationError as pe:
            raise serializers.ValidationError({"message": "Error encoding the token"})
        env: Env = Env()
        try:
            base_url: str = env('RESET_BASE_URL')
        except KeyError as ke:
            raise serializers.ValidationError({"message": "Base URL is not set"})
        try:
            link: str = f"{base_url}/reset-password/{uid}/{token}"
        except TypeError as te:
            raise serializers.ValidationError({"message": "Error creating the reset link"})
        body: str = 'Click Following Link to Reset Your Password ' + link
        data: dict[str, Any] = {
            'subject': 'Reset Your Password',
            'body': body,
            'to_email': user.email
        }

        is_success: bool = send_email(data)
        if is_success is False:
            raise serializers.ValidationError({"message": "Error sending email"})
        return attrs


class UserPasswordResetSerializer(serializers.Serializer):
    password: CharField = serializers.CharField(max_length=128, write_only=True)
    confirm_password: CharField = serializers.CharField(max_length=128, write_only=True)

    class Meta:
        fields: tuple[str, str] = ('password', 'confirm_password')

    def validate(self, attrs: OrderedDict) -> OrderedDict:
        password: str | None = attrs.get('password')
        confirm_password: str | None = attrs.get('confirm_password')
        uid: str = self.context.get('uid')
        token: str = self.context.get('token')

        if not password:
            raise serializers.ValidationError({"message": "Password is required"})
        if not confirm_password:
            raise serializers.ValidationError({"message": "Confirm Password is required"})
        if password != confirm_password:
            raise serializers.ValidationError({"message": "Password and Confirm Password do not match"})

        if uid is None:
            raise serializers.ValidationError({"message": "uid is required"})
        if token is None:
            raise serializers.ValidationError({"message": "token is required"})

        id_: Promise | str | Any = smart_str(urlsafe_base64_decode(uid))
        user: CallableUser = CallableUser.objects.filter(id=id_).first()

        if not user:
            raise serializers.ValidationError({"message": "Invalid User"})
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError({"message": "Invalid or Expired Token"})

        sub_class_user: AutoUser = CallableUser.objects.get_subclass(email=user.email)

        hashed_special_key: bytes = bcrypt.hashpw(sub_class_user.special_key, sub_class_user.salt)
        salted_password: SaltedPasswordModel = SaltedPasswordModel.objects.get(hashed_special_key=hashed_special_key)
        if password is None:
            sub_class_user.is_auto_password = False
            password: str | None = secrets.token_urlsafe(13)
        salted_password.set_password(password=password)

        with transaction.atomic():
            salted_password.save()
            sub_class_user.save()
        return attrs

    # def update(self, instance, validated_data):
    #     instance.set_password(validated_data['password'])
    #     instance.save()
    #     return instance
