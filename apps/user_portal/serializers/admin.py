from typing import Any, Mapping, NoReturn, Type

from environ import Env
from rest_framework import serializers
from rest_framework.fields import BooleanField, CharField

from apps.user_portal.exceptions import UrlSafeEncodeError, PasswordResetTokenGenerationError, SendOTPError
from apps.user_portal.models import Admin, CallableUser
from utils.email import send_email, get_uid_and_token_for_reset
from utils.inherit_types import ChildUser
from utils.otp import send_otp


class CreateAdminBySuperAdminSerializer(serializers.ModelSerializer):
    """
    This serializer handles the creation of an admin by a super admin
    """

    is_otp_verification: BooleanField = serializers.BooleanField(default=False, write_only=True)

    class Meta:
        model: Type[Admin] = Admin
        exclude: list[str] = ['groups', 'user_permissions', 'is_staff', 'is_superuser', 'is_active', 'last_login',
                              "is_auto_password"]
        extra_kwargs: dict[str, Any] = {
            'is_otp_verification': {'write_only': True},
        }

    def create(self, validated_data: dict[str, Any]) -> Admin | NoReturn:
        """
        This method creates an admin from serializer data.
        Implements the create method of ModelSerializer following fat serializer pattern.
        """

        if validated_data.get("email") is None:
            raise serializers.ValidationError({"message": "Email is required"})

        phone_number: str = validated_data.get("phone_number")
        if phone_number is None:
            raise serializers.ValidationError({"message": "Phone number is required"})

        is_otp_verification: bool = validated_data.pop('is_otp_verification')
        if is_otp_verification is None:
            raise serializers.ValidationError({"message": "Verification method is required. \
                   Specify either otp_verification or \
                   email_verification by setting is_otp_verification to True or False"})

        user: ChildUser = Admin.objects.create_user(**validated_data)
        callable_user: CallableUser = user.callableuser_ptr

        if not callable_user:
            raise serializers.ValidationError({"message": "Invalid Email"})

        if not is_otp_verification:

            try:
                token, uid = get_uid_and_token_for_reset(callable_user)
            except UrlSafeEncodeError as ue:
                raise serializers.ValidationError({"message": "Can not generate the uid"})
            except PasswordResetTokenGenerationError as pe:
                raise serializers.ValidationError({"message": "Can not generate the token"})

            env: Env = Env()

            try:
                base_url: str = env('BASE_URL')
            except KeyError as ke:
                raise serializers.ValidationError({"message": "Base URL is not set"})

            try:
                link: str = f"{base_url}/reset-password/{uid}/{token}"
            except TypeError as te:
                raise serializers.ValidationError({"message": "Can not create the reset link"})

            body: str = 'Your temp password is: ' + user.password + \
                        '. Click Following Link to Reset Your Password ' + link
            data: dict[str, str] = {
                'subject': 'Reset Your Password',
                'body': body,
                'to_email': user.email
            }

            is_success: bool = send_email(data)
            if not is_success:
                raise serializers.ValidationError({"message": "Can not send the email"})

        else:

            try:
                send_otp(user_object=callable_user, phone_number=phone_number)
            except SendOTPError as send_err:
                raise serializers.ValidationError({"message": "Can not send the OTP"})

        return user

    def to_representation(self, instance: Admin) -> Mapping[str, Any]:
        """
        This method represents the response data.
        """

        response: dict[str, Any] = super().to_representation(instance)

        try:
            response.pop('salt')
            response.pop('special_key')
        except KeyError as ke:
            raise serializers.ValidationError({"message": "Representation Error. Can not represent the response data"})

        response['message'] = 'Admin created successfully. Please check your email or phone.'

        return response


class CreateAdminSerializer(serializers.ModelSerializer):
    """
    This serializer handles the creation of an admin. Same as a register feature for admin.
    Need further approval of super admin to activate the account which is implemented in
    UserAccountActivationByOTPVerificationSerializer and
    UserAccountActivationByEmailVerificationSerializer serializers.
    """

    is_otp_verification: BooleanField = serializers.BooleanField(default=False, write_only=True)
    password: CharField = serializers.CharField(write_only=True)

    class Meta:
        model: Type[Admin] = Admin
        exclude: list[str] = ['groups', 'user_permissions', 'is_staff', 'is_superuser', 'is_active', 'last_login',
                              "is_auto_password"]
        extra_kwargs: dict[str, Any] = {
            'is_otp_verification': {'write_only': True},
            'password': {'write_only': True},
        }

    def create(self, validated_data: dict[str, Any]) -> Admin | NoReturn:
        """
        Implements the create method of ModelSerializer following fat serializer pattern.
        """

        if validated_data.get("email") is None:
            raise serializers.ValidationError({"message": "Email is required"})

        phone_number: str = validated_data.get("phone_number")
        if phone_number is None:
            raise serializers.ValidationError({"message": "Phone number is required"})

        is_otp_verification: bool = validated_data.pop('is_otp_verification')
        if is_otp_verification is None:
            raise serializers.ValidationError({"message": "Verification method is required. \
                        Specify either otp_verification or email_verification by setting is_otp_verification to True or False"})

        if validated_data.get('password') is None:
            raise serializers.ValidationError({"message": "Password is required"})

        user: ChildUser = Admin.objects.create_user(is_active=False, **validated_data)
        callable_user: CallableUser = user.callableuser_ptr

        if not callable_user:
            raise serializers.ValidationError({"message": "Invalid Email"})

        if not is_otp_verification:

            try:
                token, uid = get_uid_and_token_for_reset(callable_user)
            except UrlSafeEncodeError as ue:
                raise serializers.ValidationError({"message": "Can not generate the uid"})
            except PasswordResetTokenGenerationError as pe:
                raise serializers.ValidationError({"message": "Can not generate the token"})

            env: Env = Env()

            try:
                base_url: str = env('BASE_URL')
            except KeyError as ke:
                raise serializers.ValidationError({"message": "Base URL is not set"})

            try:
                link: str = f"{base_url}/v1/api/account/activate/verify/email/{uid}/{token}"
            except TypeError as te:
                raise serializers.ValidationError({"message": "Can not create the verification link"})

            body: str = 'Click Following Link to Verify Your Account ' + link
            data: dict[str, str] = {
                'subject': 'Verify Your Account',
                'body': body,
                'to_email': user.email
            }

            is_success: bool = send_email(data)
            if not is_success:
                raise serializers.ValidationError({"message": "Can not send the email"})

        else:

            try:
                send_otp(user_object=callable_user, phone_number=phone_number)
            except SendOTPError as send_err:
                raise serializers.ValidationError({"message": "Can not send the OTP"})

        return user

    def to_representation(self, instance: Admin) -> Mapping[str, Any]:
        """
        This method represents the response data.
        """

        response: dict[str, Any] = super().to_representation(instance)

        try:
            response.pop('salt')
            response.pop('special_key')
        except KeyError as ke:
            raise serializers.ValidationError({"message": "Representation Error. Can not represent the response data"})

        response['message'] = 'Admin created successfully. Please check your email or phone.'

        return response
