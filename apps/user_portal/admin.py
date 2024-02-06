from django.contrib import admin
from apps.user_portal.models.admin import Admin
from apps.user_portal.models.base_user import CallableUser
from apps.user_portal.models.teacher import Teacher
from apps.user_portal.models.course import Course
from apps.user_portal.models.salted_password import SaltedPasswordModel

admin.site.register(Admin)
admin.site.register(CallableUser)
admin.site.register(Teacher)
admin.site.register(SaltedPasswordModel)
admin.site.register(Course)

# Register your models here.
