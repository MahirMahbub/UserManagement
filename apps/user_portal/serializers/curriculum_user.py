from rest_framework import serializers
from rest_framework.fields import BooleanField
from rest_framework.validators import UniqueValidator
from django.db import IntegrityError
from apps.user_portal.exceptions import UserCreationError
from apps.user_portal.models.admin import Admin
from apps.user_portal.models.base_user import CallableUser


class CreateUserAbstractSerializer(serializers.Serializer):
    user_model = None
    is_otp_verification: BooleanField = serializers.BooleanField(
        default=False, write_only=True
    )
    email = serializers.EmailField(
        required=True,
        validators=[
            UniqueValidator(
                queryset=CallableUser.objects.all(),
                message="User with this email is already exists!",
            )
        ],
    )
    phone_number = serializers.CharField(max_length=10)

    def create(self, validated_data):
        # assert getattr(self, "user_model"), "Class missing user_model attribute"
        model_class = self.user_model
        validated_data.pop("is_otp_verification")
        try:
            user = model_class.objects.create_user(is_active=False, **validated_data)
        except IntegrityError as ex:
            raise UserCreationError()
        return user

    def to_representation(self, instance):
        response = super().to_representation(instance)
        if "password" in response:
            response.pop("password")
        response[
            "message"
        ] = "User created successfully. Please check your email or phone."
        return response


class CreateAdminSerializer(CreateUserAbstractSerializer):
    user_model = Admin

    # extra field for this serializer
    password = serializers.CharField()


class CreateAdminBySuperAdminSerializer(CreateUserAbstractSerializer):
    user_model = Admin
