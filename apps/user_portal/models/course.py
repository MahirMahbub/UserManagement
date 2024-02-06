from django.db import models
from .teacher import Teacher


class Course(models.Model):
    title = models.CharField(max_length=255)
    course_code = models.CharField(max_length=20, unique=True)
    credit_hour = models.PositiveSmallIntegerField()
    instructor = models.ForeignKey(
        Teacher, on_delete=models.CASCADE, related_name="courses"
    )

    def __str__(self) -> str:
        return self.title
