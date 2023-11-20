from django.contrib.auth.models import Permission
from django.db.models import Q


class PermissionMixin(object):
    @staticmethod
    def get_required_permissions() -> list[Permission]:
        """
        Get all permissions
        """

        return Permission.objects.all()

    @staticmethod
    def get_required_permissions_for_admin() -> list[Permission]:
        """
        Get required permissions for admin user
        """

        return [permission for permission in Permission.objects.exclude(Q(codename__endswith='callableuser') |
                                                                        Q(codename__endswith='logentry') |
                                                                        Q(codename__endswith='permission') |
                                                                        Q(codename__endswith='group') |
                                                                        Q(codename__endswith='session') |
                                                                        Q(codename__exact='change_saltedpasswordmodel') |
                                                                        Q(codename__exact='delete_saltedpasswordmodel'))]
