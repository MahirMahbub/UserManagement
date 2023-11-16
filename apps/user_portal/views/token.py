from rest_framework_simplejwt.views import TokenObtainPairView

from apps.user_portal.serializers.token import CustomTokenObtainPairSerializer


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer