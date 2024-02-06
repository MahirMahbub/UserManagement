from rest_framework.exceptions import APIException


class UrlSafeEncodeError(Exception):
    pass


class PasswordResetTokenGenerationError(Exception):
    pass


class UserCreationError(Exception):
    pass


class AdminCreationError(Exception):
    pass


class SuperAdminCreationError(Exception):
    pass


class TeacherCreationError(Exception):
    pass


class SendOTPError(Exception):
    pass


class UserCreationError(APIException):
    status_code = 400
    default_detail = "Cannot create user"
    default_code = "service_unavailable"
