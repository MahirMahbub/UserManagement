from apps.user_portal.models.teacher import Teacher
from .curriculum_user import CreateUserAbstractSerializer
from rest_framework import serializers
from rest_framework.validators import UniqueValidator


class CreateTeacherByAdminSerializer(CreateUserAbstractSerializer):
    user_model = Teacher
    user_name = serializers.CharField(
        validators=[
            UniqueValidator(
                queryset=Teacher.objects.all(),
                message="Teacher with this username already exists!",
            )
        ]
    )
    user_id = serializers.CharField(
        validators=[
            UniqueValidator(
                queryset=Teacher.objects.all(),
                message="Teacher with this user id already exists!",
            )
        ]
    )


class CreateTeacherSerializer(CreateTeacherByAdminSerializer):
    password = serializers.CharField()
