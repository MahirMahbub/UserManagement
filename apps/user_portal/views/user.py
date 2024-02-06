from rest_framework.mixins import CreateModelMixin
from rest_framework.viewsets import GenericViewSet
from django.db import transaction
from apps.user_portal.exceptions import SendOTPError
from utils.email import PasswordResetEmail, ActivationEmail
from utils.otp import send_otp
from rest_framework import serializers


class CreateUserViewSet(CreateModelMixin, GenericViewSet):
    serializer_class = None

    def perform_create(self, serializer: serializers):
        with transaction.atomic() as t:
            user = serializer.save()
            callable_user = user.callableuser_ptr
            if serializer.validated_data.get("is_otp_verification"):
                try:
                    send_otp(
                        callable_user, serializer.validated_data.get("phone_number")
                    )
                except SendOTPError:
                    raise serializers.ValidationError("Can't send otp!")
            ActivationEmail(self.request, context={"user": callable_user}).send(
                to=[user.email]
            )


class CreateUserByAdminViewSet(CreateModelMixin, GenericViewSet):
    serializer_class = None

    def perform_create(self, serializer):
        user = serializer.save()
        callable_user = user.callableuser_ptr
        if serializer.validated_data.get("is_otp_verification"):
            send_otp(callable_user, serializer.validated_data.get("phone_number"))
        PasswordResetEmail(self.request, context={"user": callable_user}).send(
            to=[user.email]
        )
