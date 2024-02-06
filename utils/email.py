from typing import Mapping, Any, NoReturn

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import EmailMessage
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from apps.user_portal.exceptions import (
    UrlSafeEncodeError,
    PasswordResetTokenGenerationError,
)
from config import settings
from utils.custom_types import EmailVerificationInfo
from utils.inherit_types import GenericUser
from templated_mail.mail import BaseEmailMessage


class ActivationEmail(BaseEmailMessage):
    template_name = "email/activation.html"

    def get_context_data(self):
        # ActivationEmail can be deleted
        context = super().get_context_data()
        user = context.get("user")
        token, uid = get_uid_and_token_for_reset(user)
        context["uid"] = uid
        context["token"] = token
        context["url"] = settings.ACTIVATION_URL.format(**context)
        return context


class PasswordResetEmail(BaseEmailMessage):
    template_name = "email/password_reset.html"

    def get_context_data(self):
        # ActivationEmail can be deleted
        context = super().get_context_data()

        user = context.get("user")
        token, uid = get_uid_and_token_for_reset(user)
        context["uid"] = uid
        context["token"] = token
        context["url"] = settings.PASSWORD_RESET_CONFIRM_URL.format(**context)
        return context


def send_email(data: Mapping[str, Any]) -> bool:
    try:
        email = EmailMessage(
            subject=data["subject"],
            body=data["body"],
            from_email=settings.SERVER_EMAIL,
            to=[data["to_email"]],
        )
        email.send()
    except AttributeError as e:
        return False

    except Exception as e:
        return False

    return True


def get_uid_and_token_for_reset(
    callable_user: GenericUser,
) -> NoReturn | EmailVerificationInfo:
    try:
        uid: str = urlsafe_base64_encode(force_bytes(callable_user.id))
    except TypeError as type_err:
        raise UrlSafeEncodeError(
            {"message": "Error encoding the user id"}
        ) from type_err

    try:
        token: str = PasswordResetTokenGenerator().make_token(callable_user)
    except TypeError as type_err:
        raise PasswordResetTokenGenerationError(
            {"message": "Error encoding the token"}
        ) from type_err

    return token, uid
