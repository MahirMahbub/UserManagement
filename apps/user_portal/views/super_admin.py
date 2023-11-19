from rest_framework import viewsets

from apps.user_portal.models import Admin
from apps.user_portal.permissions.super_admin import IsSuperAdmin
from apps.user_portal.serializers.admin import CreateAdminBySuperAdminSerializer, CreateAdminSerializer


class CreateAdminBySuperAdminViewSet(viewsets.ModelViewSet):
    """
    This endpoint allows a super admin to create an admin
    """
    serializer_class = CreateAdminBySuperAdminSerializer
    permission_classes = [IsSuperAdmin]
    queryset = Admin.objects.all()
    http_method_names = ['post']

    # def create(self, request, *args, **kwargs):
    #     serializer = self.get_serializer(data=request.data)
    #     if serializer.is_valid():
    #         serializer.save()
    #         return Response({"message": "Admin created successfully"}, status=status.HTTP_201_CREATED)
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CreateAdminViewSet(viewsets.ModelViewSet):
    serializer_class = CreateAdminSerializer
    queryset = Admin.objects.all()
    http_method_names = ['post']
