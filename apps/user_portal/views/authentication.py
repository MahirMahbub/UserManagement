from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.user_portal.serializers.authentication import SendPasswordResetByEmailSerializer, \
    UserPasswordResetByEmailVerificationSerializer, SendPasswordResetByOTPSerializer, \
    UserPasswordResetByOTPVerificationSerializer, UserAccountActivationByOTPVerificationSerializer, \
    UserAccountActivationByEmailVerificationSerializer


class SendPasswordResetByEmailViewSet(viewsets.GenericViewSet):
    serializer_class = SendPasswordResetByEmailSerializer

    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Password Reset link has been send. Please check your Email'},
                        status=status.HTTP_200_OK)


class SendPasswordResetByOTPViewSet(viewsets.GenericViewSet):
    serializer_class = SendPasswordResetByOTPSerializer

    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'OTP has been send. Please check your Phone'}, status=status.HTTP_200_OK)

class SendAccountActivationByEmailViewSet(viewsets.GenericViewSet):
    serializer_class = SendPasswordResetByEmailSerializer

    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Password Reset link has been send. Please check your Email'},
                        status=status.HTTP_200_OK)


class SendAccountActivationByOTPViewSet(viewsets.GenericViewSet):
    serializer_class = SendPasswordResetByOTPSerializer

    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'OTP has been send. Please check your Phone'}, status=status.HTTP_200_OK)

class UserPasswordResetByEmailVerificationViewSet(viewsets.GenericViewSet):
    serializer_class = UserPasswordResetByEmailVerificationSerializer

    def create(self, request, uid, token):
        serializer = self.get_serializer(data=request.data, context={'uid': uid, 'token': token})
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Password Reset Successfully'}, status=status.HTTP_200_OK)


class UserPasswordResetByOTPVerificationViewSet(viewsets.GenericViewSet):
    serializer_class = UserPasswordResetByOTPVerificationSerializer

    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'OTP has been send. Please check your Phone'}, status=status.HTTP_200_OK)

class UserAccountActivationByOTPVerificationViewSet(viewsets.GenericViewSet):
    serializer_class = UserAccountActivationByOTPVerificationSerializer

    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'OTP has been send. Please check your Phone'}, status=status.HTTP_200_OK)

class UserAccountActivationByEmailVerificationViewSet(viewsets.GenericViewSet):
    serializer_class = UserAccountActivationByEmailVerificationSerializer

    def create(self, request, uid, token):
        serializer = self.get_serializer(data=request.data, context={'uid': uid, 'token': token})
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Account Activation Successfully'}, status=status.HTTP_200_OK)