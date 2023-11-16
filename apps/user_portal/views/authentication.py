from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.user_portal.serializers.authentication import SendPasswordResetEmailSerializer, UserPasswordResetSerializer


class SendPasswordResetEmailViewSet(viewsets.GenericViewSet):
    serializer_class = SendPasswordResetEmailSerializer

    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)


class UserPasswordResetViewSet(viewsets.GenericViewSet):
    serializer_class = UserPasswordResetSerializer

    def create(self, request, uid, token):
        serializer = self.get_serializer(data=request.data, context={'uid':uid, 'token':token})
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Password Reset Successfully'}, status=status.HTTP_200_OK)
