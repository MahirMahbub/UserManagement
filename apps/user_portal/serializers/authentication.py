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
from utils.otp import generate_otp_object, MessageHandler


class SendPasswordResetByEmailSerializer(serializers.Serializer):
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


class SendPasswordResetByOTPSerializer(serializers.Serializer):
    email: EmailField = serializers.EmailField()
    phone_number: CharField = serializers.CharField(max_length=128)

    def validate(self, attrs: OrderedDict) -> OrderedDict:
        phone_number: str = attrs.get('phone_number')
        email: str = attrs.get('email')
        if not phone_number:
            raise serializers.ValidationError({"message": "Phone Number is required"})
        if not email:
            raise serializers.ValidationError({"message": "Email is required to check the validity of the account"})

        user = CallableUser.objects.get_subclass(email=email)
        callable_user: CallableUser = user.callableuser_ptr
        if not user:
            raise serializers.ValidationError({"message": "Invalid Phone Number"})
        try:
            otp_object = generate_otp_object(callable_user)
            otp = otp_object.now()
            MessageHandler(phone_number=phone_number,
                           otp=otp).send_otp_via_message()
        except Exception as e:
            raise serializers.ValidationError({"message": "Error sending OTP"})
        return attrs

class SendAccountActivationByEmailSerializer(serializers.Serializer):
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
            link: str = f"{base_url}/verify/{uid}/{token}"
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


class SendAccountActivationByOTPSerializer(serializers.Serializer):
    email: EmailField = serializers.EmailField()
    phone_number: CharField = serializers.CharField(max_length=128)

    def validate(self, attrs: OrderedDict) -> OrderedDict:
        phone_number: str = attrs.get('phone_number')
        email: str = attrs.get('email')
        if not phone_number:
            raise serializers.ValidationError({"message": "Phone Number is required"})
        if not email:
            raise serializers.ValidationError({"message": "Email is required to check the validity of the account"})

        user = CallableUser.objects.get_subclass(email=email)
        callable_user: CallableUser = user.callableuser_ptr
        if not user:
            raise serializers.ValidationError({"message": "Invalid Phone Number"})
        try:
            otp_object = generate_otp_object(callable_user)
            otp = otp_object.now()
            MessageHandler(phone_number=phone_number,
                           otp=otp).send_otp_via_message()
        except Exception as e:
            raise serializers.ValidationError({"message": "Error sending OTP"})
        return attrs

class UserPasswordResetByEmailVerificationSerializer(serializers.Serializer):
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
        sub_class_user.is_auto_password = False
        salted_password.set_password(password=password)

        with transaction.atomic():
            salted_password.save()
            sub_class_user.save()
        return attrs


class UserPasswordResetByOTPVerificationSerializer(serializers.Serializer):
    password: CharField = serializers.CharField(max_length=128, write_only=True)
    confirm_password: CharField = serializers.CharField(max_length=128, write_only=True)
    otp: CharField = serializers.CharField(max_length=128, write_only=True)
    email: EmailField = serializers.EmailField()

    class Meta:
        fields: tuple[str, str, str] = ('password', 'confirm_password', 'otp')

    def validate(self, attrs):
        password: str | None = attrs.get('password')
        confirm_password: str | None = attrs.get('confirm_password')
        otp: str | None = attrs.get('otp')
        email: str | None = attrs.get('email')

        sub_class_user = CallableUser.objects.get_subclass(email=email)
        if not sub_class_user:
            raise serializers.ValidationError({"message": "No associate user found with this email"})
        callable_user: CallableUser = sub_class_user.callableuser_ptr

        if not password:
            raise serializers.ValidationError({"message": "Password is required"})
        if not confirm_password:
            raise serializers.ValidationError({"message": "Confirm Password is required"})
        if password != confirm_password:
            raise serializers.ValidationError({"message": "Password and Confirm Password do not match"})
        if not otp:
            raise serializers.ValidationError({"message": "OTP is required"})
        if not email:
            raise serializers.ValidationError({"message": "Email is required"})

        env: Env = Env()

        try:
            otp_object = generate_otp_object(callable_user)
        except Exception as e:
            raise serializers.ValidationError({"message": "Error Checking OTP"})

        if not otp_object.verify(otp):
            raise serializers.ValidationError({"message": "Invalid OTP"})

        hashed_special_key: bytes = bcrypt.hashpw(sub_class_user.special_key, sub_class_user.salt)
        salted_password: SaltedPasswordModel = SaltedPasswordModel.objects.get(hashed_special_key=hashed_special_key)
        salted_password.set_password(password=password)

        with transaction.atomic():
            salted_password.save()
            sub_class_user.save()
        return attrs
    
class UserAccountActivationByOTPVerificationSerializer(serializers.Serializer):
    otp: CharField = serializers.CharField(max_length=128, write_only=True)
    email: EmailField = serializers.EmailField()

    class Meta:
        fields: tuple[str, str] = ('otp')

    def validate(self, attrs):
        otp: str | None = attrs.get('otp')
        email: str | None = attrs.get('email')

        sub_class_user = CallableUser.objects.get_subclass(email=email)
        if not sub_class_user:
            raise serializers.ValidationError({"message": "No associate user found with this email"})
        callable_user: CallableUser = sub_class_user.callableuser_ptr

        if not otp:
            raise serializers.ValidationError({"message": "OTP is required"})
        if not email:
            raise serializers.ValidationError({"message": "Email is required"})

        env: Env = Env()

        try:
            otp_object = generate_otp_object(callable_user)
        except Exception as e:
            raise serializers.ValidationError({"message": "Error Checking OTP"})

        if not otp_object.verify(otp):
            raise serializers.ValidationError({"message": "Invalid OTP"})

        sub_class_user.is_active = True
        sub_class_user.save()
        return attrs

class UserAccountActivationByEmailVerificationSerializer(serializers.Serializer):
    email: EmailField = serializers.EmailField()

    class Meta:
        fields: tuple[str, str] = ('email')

    def validate(self, attrs):
        email: str | None = attrs.get('email')
        uid: str = self.context.get('uid')
        token: str = self.context.get('token')

        if not email:
            raise serializers.ValidationError({"message": "Email is required"})
        if not uid:
            raise serializers.ValidationError({"message": "uid is required"})
        if not token:
            raise serializers.ValidationError({"message": "token is required"})

        id_: Promise | str | Any = smart_str(urlsafe_base64_decode(uid))
        user: CallableUser = CallableUser.objects.filter(id=id_).first()

        if not user:
            raise serializers.ValidationError({"message": "Invalid User"})

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError({"message": "Invalid or Expired Token"})

        sub_class_user: AutoUser = CallableUser.objects.get_subclass(email=user.email)
        sub_class_user.is_active = True
        sub_class_user.save()
        return attrs


