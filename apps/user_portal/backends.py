import bcrypt
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend, ModelBackend

from apps.user_portal.models import GenericUser, SaltedPasswordModel
from apps.user_portal.models.super_admin import SuperAdmin


class CustomAdminBackend(ModelBackend):
    model = GenericUser

    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = self.model.objects.get(email=username)
        except self.model.DoesNotExist:
            return None

        if user.is_superuser:
            try:
                admin = SuperAdmin.objects.get(email=username)
            except SuperAdmin.DoesNotExist:
                return None
            if self.check_password(password, admin) and self.user_can_authenticate(user):
                return user
            else:
                return None
        return user

    def user_can_authenticate(self, user):
        """
        Reject users with is_active=False. Custom user models that don't have
        that attribute are allowed.
        """
        email = getattr(user, "email", None)
        if email is None:
            return False
        try:
            admin = SuperAdmin.objects.get(email=email)
        except SuperAdmin.DoesNotExist:
            return False
        return getattr(admin, "is_active", False)


    def get_user(self, user_id):
        try:
            return self.model.objects.get(pk=user_id)
        except self.model.DoesNotExist:
            return None

    @staticmethod
    def check_password(password, admin):
        special_key = admin.special_key
        if special_key is None:
            return False
        encoded_special_key = special_key
        hashed_special_key = bcrypt.hashpw(encoded_special_key, admin.salt)
        password_obj = SaltedPasswordModel.objects.get(hashed_special_key=hashed_special_key)
        if password_obj is not None:
            check_password = bcrypt.checkpw(password.encode('utf-8'), password_obj.password)
            if check_password:
                return True
            else:
                return False
        return False
