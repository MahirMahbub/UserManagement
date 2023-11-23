from typing import Any, NoReturn, Mapping

import bcrypt
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.db import transaction
from django.utils.encoding import smart_str
from django.utils.functional import Promise
from django.utils.http import urlsafe_base64_decode
from environ import Env
from rest_framework import serializers
from rest_framework.fields import EmailField, CharField

from apps.user_portal.exceptions import UrlSafeEncodeError, PasswordResetTokenGenerationError, SendOTPError
from apps.user_portal.models import CallableUser, SaltedPasswordModel
from utils.email import send_email, get_uid_and_token_for_reset
from utils.inherit_types import ChildUser
from utils.otp import generate_otp_object, send_otp


class SendPasswordResetByEmailSerializer(serializers.Serializer):
    """
    This serializer handles the sending of password reset email.
    the email is sent to the user's email address with a link to reset the password.
    """

    email: EmailField = serializers.EmailField(required=True)

    def validate(self, attrs: Mapping[str, Any]) -> Mapping[str, Any] | NoReturn:
        """
        This method validates the serializer data. It checks if the email is valid and if the user exists.
        It also generates the reset link and sends the email.
        If the user does not receive the email, they can request for a new one.
        """

        email: str = attrs.get('email')
        if not email:
            raise serializers.ValidationError({"message": "Email is required"})

        callable_user: CallableUser = CallableUser.objects.filter(email=email).first()
        if not callable_user:
            raise serializers.ValidationError({"message": "Invalid Email, No account found"})

        try:
            token, uid = get_uid_and_token_for_reset(callable_user)
        except UrlSafeEncodeError as ue:
            raise serializers.ValidationError({"message": "Error encoding the user id"})
        except PasswordResetTokenGenerationError as pe:
            raise serializers.ValidationError({"message": "Error encoding the token"})

        env: Env = Env()

        try:
            base_url: str = env('BASE_URL')
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
            'to_email': callable_user.email
        }

        is_success: bool = send_email(data)
        if is_success is False:
            raise serializers.ValidationError({"message": "Error sending email"})

        return attrs


class SendPasswordResetByOTPSerializer(serializers.Serializer):
    """
    This serializer handles the sending OTP to reset password. The OTP is sent to the user's phone number.

    """

    email: EmailField = serializers.EmailField(required=True)
    phone_number: CharField = serializers.CharField(max_length=128, required=True)

    def validate(self, attrs: Mapping[str, Any]) -> Mapping[str, Any] | NoReturn:
        """
        This method validates the serializer data. It checks if the email, phone number is valid and if the user exists.
        It also generates the OTP and sends it to the user's phone number.
        The OTP is valid for 5 minutes. If the user does not receive the OTP or expired, they can request for a new one.
        """

        phone_number: str = attrs.get('phone_number')
        if not phone_number:
            raise serializers.ValidationError({"message": "Phone Number is required"})

        email: str = attrs.get('email')
        if not email:
            raise serializers.ValidationError({"message": "Email is required to check the validity of the account"})

        user: ChildUser = CallableUser.objects.get_subclass(email=email)
        if not user:
            raise serializers.ValidationError({"message": "Invalid Email, No account found"})

        callable_user: CallableUser = user.callableuser_ptr

        if user.phone_number != phone_number:
            raise serializers.ValidationError({"message": "Phone Number do not match with the \
                                                account registered phone number"})
        try:
            send_otp(user_object=callable_user, phone_number=phone_number)
        except SendOTPError as send_err:
            raise serializers.ValidationError({"message": "Can not send the OTP"})

        return attrs


class SendAccountActivationByEmailSerializer(serializers.Serializer):
    email: EmailField = serializers.EmailField(required=True)

    def validate(self, attrs: Mapping[str, Any]) -> Mapping[str, Any] | NoReturn:
        """
        This method validates the serializer data. It checks if the email is valid and if the user exists.
        It also generates the reset link and sends the email. The link is used to activate the user's account.
        If the user does not receive the email, they can request for a new one.
        """

        email: str = attrs.get('email')
        if not email:
            raise serializers.ValidationError({"message": "Email is required"})

        user: CallableUser = CallableUser.objects.filter(email=email).first()
        if not user:
            raise serializers.ValidationError({"message": "Invalid Email, No account found"})

        try:
            token, uid = get_uid_and_token_for_reset(user)
        except UrlSafeEncodeError as ue:
            raise serializers.ValidationError({"message": "Error encoding the user id"})
        except PasswordResetTokenGenerationError as pe:
            raise serializers.ValidationError({"message": "Error encoding the token"})

        env: Env = Env()

        try:
            base_url: str = env('BASE_URL')
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

    def validate(self, attrs: Mapping[str, Any]) -> Mapping[str, Any] | NoReturn:
        """
        This method validates the serializer data. It checks if the email, phone number is valid and if the user exists.
        It also generates the OTP and sends it to the user's phone number. The OTP is used to activate the user's account.
        The OTP is valid for 5 minutes. If the user does not receive the OTP or expired, they can request for a new one.

        """

        phone_number: str = attrs.get('phone_number')
        if not phone_number:
            raise serializers.ValidationError({"message": "Phone Number is required"})

        email: str = attrs.get('email')
        if not email:
            raise serializers.ValidationError({"message": "Email is required to check the validity of the account"})

        user = CallableUser.objects.get_subclass(email=email)
        if not user:
            raise serializers.ValidationError({"message": "Invalid Phone Number"})

        callable_user: CallableUser = user.callableuser_ptr

        try:
            send_otp(user_object=callable_user, phone_number=phone_number)
        except SendOTPError as send_err:
            raise serializers.ValidationError({"message": "Can not send the OTP"})
        return attrs


class UserPasswordResetByEmailVerificationSerializer(serializers.Serializer):
    password: CharField = serializers.CharField(max_length=128, write_only=True)
    confirm_password: CharField = serializers.CharField(max_length=128, write_only=True)

    class Meta:
        fields: tuple[str, str] = ('password', 'confirm_password')

    def validate(self, attrs: Mapping[str, Any]) -> Mapping[str, Any] | NoReturn:
        """
        This method validates the serializer data. It checks if the password and confirm password match.
        It also checks if the user exists and if the token is valid. If the token is valid, the user's password is reset.
        """

        password: str | None = attrs.get('password')
        if not password:
            raise serializers.ValidationError({"message": "Password is required"})

        confirm_password: str | None = attrs.get('confirm_password')
        if not confirm_password:
            raise serializers.ValidationError({"message": "Confirm Password is required"})

        if password != confirm_password:
            raise serializers.ValidationError({"message": "Password and Confirm Password do not match"})

        uid: str = self.context.get('uid')
        if uid is None:
            raise serializers.ValidationError({"message": "uid is required"})

        token: str = self.context.get('token')
        if token is None:
            raise serializers.ValidationError({"message": "token is required"})

        id_: Promise | str | Any = smart_str(urlsafe_base64_decode(uid))

        user: CallableUser = CallableUser.objects.filter(id=id_).first()
        if not user:
            raise serializers.ValidationError({"message": "Invalid User"})

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError({"message": "Invalid or Expired Token"})

        sub_class_user: ChildUser = CallableUser.objects.get_subclass(email=user.email)

        hashed_special_key: bytes = bcrypt.hashpw(sub_class_user.special_key, sub_class_user.salt)
        salted_password: SaltedPasswordModel = SaltedPasswordModel.objects.get(hashed_special_key=hashed_special_key)
        salted_password.set_password(password=password)

        sub_class_user.is_auto_password = False

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

    def validate(self, attrs: Mapping[str, Any]) -> Mapping[str, Any] | NoReturn:
        """
        This method validates the serializer data. It checks if the password and confirm password match.
        It also checks if the user exists and if the OTP is valid. If the OTP is valid, the user's password is reset.
        """
        password: str | None = attrs.get('password')
        if not password:
            raise serializers.ValidationError({"message": "Password is required"})

        confirm_password: str | None = attrs.get('confirm_password')
        if not confirm_password:
            raise serializers.ValidationError({"message": "Confirm Password is required"})

        if password != confirm_password:
            raise serializers.ValidationError({"message": "Password and Confirm Password do not match"})

        otp: str | None = attrs.get('otp')
        if not otp:
            raise serializers.ValidationError({"message": "OTP is required"})

        email: str | None = attrs.get('email')
        if not email:
            raise serializers.ValidationError({"message": "Email is required"})

        sub_class_user: ChildUser = CallableUser.objects.get_subclass(email=email)
        if not sub_class_user:
            raise serializers.ValidationError({"message": "No associate user found with this email"})

        callable_user: CallableUser = sub_class_user.callableuser_ptr

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
        fields: tuple[str, str] = ('otp',)

    def validate(self, attrs: Mapping[str, Any]) -> Mapping[str, Any] | NoReturn:
        """
        This method validates the serializer data. It checks if the user exists and if the OTP is valid.
        If the OTP is valid, the user's account is activated.
        """

        otp: str | None = attrs.get('otp')
        if not otp:
            raise serializers.ValidationError({"message": "OTP is required"})

        email: str | None = attrs.get('email')
        if not email:
            raise serializers.ValidationError({"message": "Email is required"})

        sub_class_user: ChildUser = CallableUser.objects.get_subclass(email=email)
        if not sub_class_user:
            raise serializers.ValidationError({"message": "No associate user found with this email"})

        callable_user: CallableUser = sub_class_user.callableuser_ptr

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
        fields: tuple[str, str] = ('email',)

    def validate(self, attrs: Mapping[str, Any]) -> Mapping[str, Any] | NoReturn:
        """
        This method validates the serializer data. It checks if the user exists and if the token is valid.
        If the token is valid, the user's account is activated. The link is sent to the user's email address.
        If the user does not receive the email, they can request for a new one.
        The link is used to activate the user's account.
        """
        email: str | None = attrs.get('email')
        if not email:
            raise serializers.ValidationError({"message": "Email is required"})

        uid: str = self.context.get('uid')
        if not uid:
            raise serializers.ValidationError({"message": "uid is required"})

        token: str = self.context.get('token')
        if not token:
            raise serializers.ValidationError({"message": "token is required"})

        id_: Promise | str | Any = smart_str(urlsafe_base64_decode(uid))
        user: CallableUser = CallableUser.objects.filter(id=id_).first()

        if not user:
            raise serializers.ValidationError({"message": "Invalid User"})

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError({"message": "Invalid or Expired Token"})

        sub_class_user: ChildUser = CallableUser.objects.get_subclass(email=user.email)
        sub_class_user.is_active = True
        sub_class_user.save()
        return attrs
