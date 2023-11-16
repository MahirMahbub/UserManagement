import secrets

import bcrypt
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.db import transaction
from django.utils.encoding import force_bytes, smart_str
import environ
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import serializers

from apps.user_portal.models import CallableUser, SaltedPasswordModel
from utils.email import send_email


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, attrs):
        email = attrs.get('email')
        if not email:
            raise serializers.ValidationError({"message": "Email is required"})
        user = CallableUser.objects.filter(email=email).first()
        if not user:
            raise serializers.ValidationError({"message": "Invalid Email"})
        uid = urlsafe_base64_encode(force_bytes(user.id))
        token = PasswordResetTokenGenerator().make_token(user)
        env = environ.Env()
        link = f"{env('RESET_BASE_URL')}/reset-password/{uid}/{token}"
        body = 'Click Following Link to Reset Your Password ' + link
        data = {
            'subject': 'Reset Your Password',
            'body': body,
            'to_email': user.email
        }
        send_email(data)
        return attrs


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=128, write_only=True)
    confirm_password = serializers.CharField(max_length=128, write_only=True)

    class Meta:
        fields = ('password', 'confirm_password')

    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        uid = self.context.get('uid')
        token = self.context.get('token')

        if not password:
            raise serializers.ValidationError({"message": "Password is required"})
        if not confirm_password:
            raise serializers.ValidationError({"message": "Confirm Password is required"})
        if password != confirm_password:
            raise serializers.ValidationError({"message": "Password and Confirm Password do not match"})
        id_ = smart_str(urlsafe_base64_decode(uid))
        user = CallableUser.objects.filter(id=id_).first()

        if not user:
            raise serializers.ValidationError({"message": "Invalid User"})
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError({"message": "Invalid or Expired Token"})

        sub_class_user = CallableUser.objects.get_subclass(email=user.email)

        hashed_special_key = bcrypt.hashpw(sub_class_user.special_key, sub_class_user.salt)
        salted_password = SaltedPasswordModel.objects.get(hashed_special_key=hashed_special_key)
        if password is None:
            # salted_password.is_auto_password = True
            sub_class_user.is_auto_password = False
            password = secrets.token_urlsafe(13)
        salted_password.set_password(password=password)

        with transaction.atomic():
            salted_password.save()
            sub_class_user.save()
        return attrs

    def update(self, instance, validated_data):
        instance.set_password(validated_data['password'])
        instance.save()
        return instance
