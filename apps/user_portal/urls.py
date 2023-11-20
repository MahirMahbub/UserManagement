from django.urls import include, path

from .serializers.authentication import SendPasswordResetByOTPSerializer
from .views import *
from rest_framework.routers import DefaultRouter

from .views.authentication import SendPasswordResetByEmailViewSet, UserPasswordResetByEmailVerificationViewSet, \
    SendPasswordResetByOTPViewSet, UserPasswordResetByOTPVerificationViewSet, \
    UserAccountActivationByEmailVerificationViewSet, UserAccountActivationByOTPVerificationViewSet, \
    SendAccountActivationByEmailViewSet, SendAccountActivationByOTPViewSet
from .views.super_admin import CreateAdminBySuperAdminViewSet, CreateAdminViewSet

app_name = "card_portal"
router = DefaultRouter()
router.register(r"super-admin/admins", CreateAdminBySuperAdminViewSet, basename="create_admin")
router.register(r"password/reset/email", SendPasswordResetByEmailViewSet, basename="send-reset-password-email")
router.register(r"password/reset/otp", SendPasswordResetByOTPViewSet, basename="send-reset-password-otp")
router.register(r"account/verify/email", SendAccountActivationByEmailViewSet, basename="send-account-activation-email")
router.register(r"account/verify/otp", SendAccountActivationByOTPViewSet, basename="send-account-activation-otp")
router.register(r"password/reset/change/otp", UserPasswordResetByOTPVerificationViewSet, basename="reset-password-otp")
router.register(r"account/activate/verify/otp", UserAccountActivationByOTPVerificationViewSet, basename="activate-account-otp")
router.register(r"admins/register", CreateAdminViewSet, basename="create-admin")


# router.register(r"reset-password/<uid>/<token>", UserPasswordResetViewSet, basename="reset-password")
urlpatterns = [
    path("", include(router.urls)),
    path("password/reset/change/email/<uid>/<token>", UserPasswordResetByEmailVerificationViewSet.as_view({"post": "create"}), name="reset-password"),
    path("account/activate/verify/email/<uid>/<token>", UserAccountActivationByEmailVerificationViewSet.as_view({"post": "create"}), name="reset-password"),]