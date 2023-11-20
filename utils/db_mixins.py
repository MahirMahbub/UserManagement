from django.db import models
from django.db.models import DateTimeField


class TimeStampModelMixin(models.Model):
    created_at: DateTimeField = models.DateTimeField(auto_now_add=True)
    updated_at: DateTimeField = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class BaseModelMixin(TimeStampModelMixin):
    class Meta:
        abstract = True
