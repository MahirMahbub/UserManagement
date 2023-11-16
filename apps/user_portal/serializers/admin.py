import environ
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework import serializers

from apps.user_portal.models import Admin, CallableUser
from django.core.mail import send_mail
from django.conf import settings

from utils.email import send_email


class AdminSerializer(serializers.ModelSerializer):
    """
    This serializer handles the creation of an admin
    """

    # password = serializers.CharField(min_length=5)
    class Meta:
        model = Admin
        # fields = '__all__'
        exclude = ['groups', 'user_permissions', 'is_staff', 'is_superuser', 'is_active', 'last_login',
                   "is_auto_password"]
        # extra_kwargs = {
        #     'password': {'write_only': True}
        # }

    def create(self, validated_data):
        user = Admin.objects.create_user(**validated_data)
        callable_user = CallableUser.objects.filter(email=user.email).first()
        if not callable_user:
            raise serializers.ValidationError({"message": "Invalid Email"})
        uid = urlsafe_base64_encode(force_bytes(callable_user.id))
        token = PasswordResetTokenGenerator().make_token(callable_user)
        env = environ.Env()
        link = f"{env('RESET_BASE_URL')}/reset-password/{uid}/{token}"
        body = 'Your temp password is: '+user.password+'Click Following Link to Reset Your Password ' + link
        data = {
            'subject': 'Reset Your Password',
            'body': body,
            'to_email': user.email
        }
        send_email(data)
        return user

    def to_representation(self, instance):

        response = super().to_representation(instance)
        response.pop('salt')
        response.pop('special_key')
        response['message'] = 'Admin created successfully. Please check your email for your temp password and reset link.'
        return response
