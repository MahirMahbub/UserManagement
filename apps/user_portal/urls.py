from django.urls import include, path

from .views import *
from rest_framework.routers import DefaultRouter

from .views.authentication import SendPasswordResetEmailViewSet, UserPasswordResetViewSet
from .views.super_admin import CreateAdminViewSet

app_name = "card_portal"
router = DefaultRouter()
router.register(r"create-admin", CreateAdminViewSet, basename="create_admin")
router.register(r"send-reset-password-email", SendPasswordResetEmailViewSet, basename="send-reset-password-email")
# router.register(r"reset-password/<uid>/<token>", UserPasswordResetViewSet, basename="reset-password")
urlpatterns = [
    path("", include(router.urls)),
    path("reset-password/<uid>/<token>", UserPasswordResetViewSet.as_view({"post": "create"}), name="reset-password"),
]