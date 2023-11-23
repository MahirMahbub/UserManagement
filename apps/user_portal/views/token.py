from typing import Type

from rest_framework import serializers
from rest_framework_simplejwt.views import TokenObtainPairView

from apps.user_portal.serializers.token import CustomTokenObtainPairSerializer


class CustomTokenObtainPairView(TokenObtainPairView):
    """
    This endpoint allows to get access and refresh token.
    """
    serializer_class: Type[serializers.Serializer] = CustomTokenObtainPairSerializer
