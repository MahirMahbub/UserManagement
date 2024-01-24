from apps.user_portal.managers.curriculum_user import CurriculumUserManager
from apps.user_portal.permissions.admin import AdminPermissions
from utils.permission_mixins import PermissionMixin


class AdminManager(CurriculumUserManager, PermissionMixin):
    """
    Manager for all Admin Users.
    """
    permissions = AdminPermissions()
