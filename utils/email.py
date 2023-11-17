import environ
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import EmailMessage
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from apps.user_portal.exceptions import UrlSafeEncodeError, PasswordResetTokenGenerationError
from apps.user_portal.models import CallableUser
from config import settings


def send_email(data):
    try:
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            from_email=settings.SERVER_EMAIL,
            to=[data['to_email']]
        )
        email.send()
    except AttributeError as e:
        return False
    return True


def get_uid_and_token_for_reset(callable_user: CallableUser) -> (str, str):
    try:
        uid: str = urlsafe_base64_encode(force_bytes(callable_user.id))
    except TypeError as e:
        raise UrlSafeEncodeError({"message": "Error encoding the user id"})
    try:
        token: str = PasswordResetTokenGenerator().make_token(callable_user)
    except TypeError as e:
        raise PasswordResetTokenGenerationError({"message": "Error encoding the token"})
    return token, uid
