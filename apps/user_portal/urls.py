from django.urls import include, path

from .serializers.authentication import SendPasswordResetByOTPSerializer
from .views import *
from rest_framework.routers import DefaultRouter

from .views.authentication import SendPasswordResetByEmailViewSet, UserPasswordResetByEmailVerificationViewSet, \
    SendPasswordResetByOTPViewSet, UserPasswordResetByOTPVerificationViewSet
from .views.super_admin import CreateAdminViewSet

app_name = "card_portal"
router = DefaultRouter()
router.register(r"create-admin", CreateAdminViewSet, basename="create_admin")
router.register(r"send-reset-password-email", SendPasswordResetByEmailViewSet, basename="send-reset-password-email")
router.register(r"send-reset-password-otp", SendPasswordResetByOTPViewSet, basename="send-reset-password-otp")
router.register(r"reset-password-otp", UserPasswordResetByOTPVerificationViewSet, basename="reset-password-otp")


# router.register(r"reset-password/<uid>/<token>", UserPasswordResetViewSet, basename="reset-password")
urlpatterns = [
    path("", include(router.urls)),
    path("reset-password-email/<uid>/<token>", UserPasswordResetByEmailVerificationViewSet.as_view({"post": "create"}), name="reset-password"),
]