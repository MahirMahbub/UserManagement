from rest_framework.viewsets import ModelViewSet
from apps.user_portal.models.course import Course
from apps.user_portal.permissions.teacher import IsTeacher, IsTeacherOrReadOnly
from apps.user_portal.serializers.course import CourseSerializer
from rest_framework_simplejwt.authentication import JWTAuthentication


class CourseViewSet(ModelViewSet):
    serializer_class = CourseSerializer
    permission_classes = [IsTeacher]

    def get_serializer_context(self):
        return {"instructor_id": self.request.user.id}

    def get_queryset(self):
        return Course.objects.all()
        # return Course.objects.filter(instructor_id=self.request.user.id)
