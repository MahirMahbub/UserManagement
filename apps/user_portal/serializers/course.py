from rest_framework import serializers
from apps.user_portal.models.teacher import Teacher
from apps.user_portal.models.course import Course


class InstructorSerializer(serializers.ModelSerializer):
    # user_name = serializers.ReadOnlyField(source="teacher.user_name")
    # user_id = serializers.ReadOnlyField(source="teacher.user_id")
    # phone_number = serializers.ReadOnlyField(source="teacher.phone_number")

    class Meta:
        model = Teacher
        fields = ["id", "email", "user_name", "user_id", "phone_number"]


class CourseSerializer(serializers.ModelSerializer):
    instructor = InstructorSerializer(read_only=True)

    class Meta:
        model = Course
        fields = [
            "id",
            "title",
            "course_code",
            "credit_hour",
            "instructor",
        ]

    def create(self, validated_data):
        instructor_id = self.context["instructor_id"]
        return Course.objects.create(**validated_data, instructor_id=instructor_id)
        # return super().save(**kwargs)
