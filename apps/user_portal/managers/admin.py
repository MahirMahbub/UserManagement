from apps.user_portal.managers.curriculum_user import CurriculumUserManager
from apps.user_portal.permissions.admin import AdminPermissions


class AdminManager(CurriculumUserManager):
    """
    Manager for all Admin Users.
    """

    permissions = AdminPermissions()
