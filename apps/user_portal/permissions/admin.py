from django.contrib.auth.models import Permission
from django.db.models import Q
from rest_framework.permissions import BasePermission


class AdminPermissions(BasePermission):
    def get_permissions(self):
        return [
            permission
            for permission in Permission.objects.exclude(
                Q(codename__endswith="callableuser")
                | Q(codename__endswith="logentry")
                | Q(codename__endswith="permission")
                | Q(codename__endswith="group")
                | Q(codename__endswith="session")
                | Q(codename__exact="change_saltedpasswordmodel")
                | Q(codename__exact="delete_saltedpasswordmodel")
            )
        ]
