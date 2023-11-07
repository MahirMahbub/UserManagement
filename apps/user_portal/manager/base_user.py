from django.contrib.auth.base_user import BaseUserManager as DjBaseUserManager
from django.utils import timezone
from model_utils.managers import InheritanceManager


from apps.user_portal.models.teacher import Teacher


class BaseUserManager(DjBaseUserManager, InheritanceManager):
    """
    Manager for all Users types
    create_user() and create_superuser() must be overriden as we do not use
    unique username but unique email.
    """

    def create_user_(self, email=None, password=None, **extra_fields):
        from apps.user_portal.models import GenericUser
        now = timezone.now()
        email = BaseUserManager.normalize_email(email)
        u = GenericUser(email=email, is_superuser=False, last_login=now,
                        **extra_fields)
        u.save(using=self._db)
        return u

    # def create_teacher(self, email=None, password=None, **extra_fields):
    #     now = timezone.now()
    #     email = BaseUserManager.normalize_email(email)
    #     u = Teacher(email=email, is_superuser=False, last_login=now,
    #                 **extra_fields)
    #     u.set_password(password)
    #     u.save(using=self._db)
    #     return u

    # def create_student(self, email, password, **extra_fields):
    #     u = self.create_user_(email, password, **extra_fields)
    #     u.is_superuser = True
    #     u.save(using=self._db)
    #     return u
