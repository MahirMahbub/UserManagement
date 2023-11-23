from typing import Type

from rest_framework import viewsets, status, serializers
from rest_framework.request import Request
from rest_framework.response import Response

from apps.user_portal.serializers.authentication import SendPasswordResetByEmailSerializer, \
    UserPasswordResetByEmailVerificationSerializer, SendPasswordResetByOTPSerializer, \
    UserPasswordResetByOTPVerificationSerializer, UserAccountActivationByOTPVerificationSerializer, \
    UserAccountActivationByEmailVerificationSerializer


class SendPasswordResetByEmailViewSet(viewsets.GenericViewSet):
    """
    This endpoint allows to send password reset link to user's email.
    """
    serializer_class: Type[serializers.Serializer] = SendPasswordResetByEmailSerializer

    def create(self, request: Request) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Password Reset link has been send. Please check your Email'},
                        status=status.HTTP_200_OK)


class SendPasswordResetByOTPViewSet(viewsets.GenericViewSet):
    """
    This endpoint allows to send password reset OTP to user's phone.
    """
    serializer_class: Type[serializers.Serializer] = SendPasswordResetByOTPSerializer

    def create(self, request: Request) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'OTP has been send. Please check your Phone'}, status=status.HTTP_200_OK)


class SendAccountActivationByEmailViewSet(viewsets.GenericViewSet):
    """
    This endpoint allows to send account activation link to user's email.
    """
    serializer_class: Type[serializers.Serializer] = SendPasswordResetByEmailSerializer

    def create(self, request: Request) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Password Reset link has been send. Please check your Email'},
                        status=status.HTTP_200_OK)


class SendAccountActivationByOTPViewSet(viewsets.GenericViewSet):
    """
    This endpoint allows to send account activation OTP to user's phone.
    """
    serializer_class: Type[serializers.Serializer] = SendPasswordResetByOTPSerializer

    def create(self, request: Request) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'OTP has been send. Please check your Phone'}, status=status.HTTP_200_OK)


class UserPasswordResetByEmailVerificationViewSet(viewsets.GenericViewSet):
    """
    This endpoint allows to reset password by email verification.
    """
    serializer_class: Type[serializers.Serializer] = UserPasswordResetByEmailVerificationSerializer

    def create(self, request: Request, uid: str, token: str) -> Response:
        serializer = self.get_serializer(data=request.data, context={'uid': uid, 'token': token})
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Password Reset Successfully'}, status=status.HTTP_200_OK)


class UserPasswordResetByOTPVerificationViewSet(viewsets.GenericViewSet):
    """
    This endpoint allows to reset password by OTP verification.
    """
    serializer_class: Type[serializers.Serializer] = UserPasswordResetByOTPVerificationSerializer

    def create(self, request: Request) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'OTP Verification Complete. Password is reset.'}, status=status.HTTP_200_OK)


class UserAccountActivationByOTPVerificationViewSet(viewsets.GenericViewSet):
    """
    This endpoint allows to activate account by OTP verification.
    """
    serializer_class: Type[serializers.Serializer] = UserAccountActivationByOTPVerificationSerializer

    def create(self, request: Request) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Account verified by OTP'}, status=status.HTTP_200_OK)


class UserAccountActivationByEmailVerificationViewSet(viewsets.GenericViewSet):
    """
    This endpoint allows to activate account by email verification.
    """
    serializer_class: Type[serializers.Serializer] = UserAccountActivationByEmailVerificationSerializer

    def create(self, request: Request, uid: str, token: str) -> Response:
        serializer = self.get_serializer(data=request.data, context={'uid': uid, 'token': token})
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Account Activation Successfully'}, status=status.HTTP_200_OK)
