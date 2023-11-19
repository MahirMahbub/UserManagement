from typing import Any, OrderedDict, Type

from environ import Env
from rest_framework import serializers

from apps.user_portal.exceptions import UrlSafeEncodeError, PasswordResetTokenGenerationError
from apps.user_portal.models import Admin, CallableUser
from utils.email import send_email, get_uid_and_token_for_reset
from utils.otp import MessageHandler, generate_otp_object


class AdminSerializer(serializers.ModelSerializer):
    """
    This serializer handles the creation of an admin
    """
    is_otp_verification: bool = serializers.BooleanField(default=False, write_only=True)

    class Meta:
        model: Type[Admin] = Admin
        exclude: list[str] = ['groups', 'user_permissions', 'is_staff', 'is_superuser', 'is_active', 'last_login',
                              "is_auto_password"]
        extra_kwargs: dict[str, Any] = {
            'is_otp_verification': {'write_only': True}
        }

    def create(self, validated_data: dict[str, Any]) -> Admin:
        is_otp_verification: bool = validated_data.pop('is_otp_verification')
        user: Admin = Admin.objects.create_user(**validated_data)
        callable_user: CallableUser = CallableUser.objects.filter(email=user.email).first()
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
                base_url: str = env('RESET_BASE_URL')
            except KeyError as ke:
                raise serializers.ValidationError({"message": "Base URL is not set"})
            try:
                link: str = f"{base_url}/reset-password/{uid}/{token}"
            except TypeError as te:
                raise serializers.ValidationError({"message": "Can not create the reset link"})
            body: str = 'Your temp password is: ' + user.password + '. Click Following Link to Reset Your Password ' + link
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
                otp_object = generate_otp_object(callable_user)
                otp = otp_object.now()
                MessageHandler(phone_number=validated_data['phone_number'],
                               otp=otp).send_otp_via_message()
            except AttributeError as ae:
                raise serializers.ValidationError({"message": "Can not send the OTP"})
            except Exception as e:
                raise serializers.ValidationError({"message": "Can not send the OTP"})
        return user

    def to_representation(self, instance: Admin) -> OrderedDict:

        response: OrderedDict = super().to_representation(instance)
        try:
            response.pop('salt')
            response.pop('special_key')
        except KeyError as ke:
            raise serializers.ValidationError({"message": "Representation Error. Can not represent the response data"})
        response['message'] = ('Admin created successfully. Please check your email for your temp password and reset '
                               'link.')
        return response
