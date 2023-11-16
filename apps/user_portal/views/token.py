from rest_framework_simplejwt.views import TokenObtainPairView

from apps.user_portal.serializers.token import MyTokenObtainPairSerializer


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer