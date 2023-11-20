from typing import Type, NoReturn

from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.utils.translation import gettext_lazy as _
from drf_spectacular.contrib.rest_framework_simplejwt import SimpleJWTScheme
from rest_framework import HTTP_HEADER_ENCODING
from rest_framework.authtoken.models import Token
from rest_framework.request import Request
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import AuthenticationFailed, TokenError, InvalidToken
from rest_framework_simplejwt.settings import api_settings

from utils.protocols import SequenceToken
from utils.custom_types import Params, DetailedMessage
from utils.inherit_types import ChildUser

# from custom_types import GenericUser, Params, DetailedMessage, ChildUser


AUTH_HEADER_TYPES = api_settings.AUTH_HEADER_TYPES

if not isinstance(api_settings.AUTH_HEADER_TYPES, (list, tuple)):
    AUTH_HEADER_TYPES = (AUTH_HEADER_TYPES,)

AUTH_HEADER_TYPE_BYTES: set[bytes] = {
    h.encode(HTTP_HEADER_ENCODING) for h in AUTH_HEADER_TYPES
}


class CustomJWTAuthentication(JWTAuthentication):
    """
    An authentication plugin that authenticates requests through a JSON web
    token provided in a request header.
    """
    from apps.user_portal.models import CallableUser

    user_model: Type[AbstractBaseUser]

    www_authenticate_realm = "api"
    media_type = "application/json"
    user_class = CallableUser

    def __init__(self, *args: Params.args, **kwargs: Params.kwargs) -> None:

        super().__init__(*args, **kwargs)

        from apps.user_portal.models import CallableUser

        self.user_model = CallableUser

    def authenticate(self, request: Request) -> AbstractBaseUser | NoReturn | None:

        header: bytes | None = self.get_header(request)
        if header is None:
            return None

        raw_token: bytes | None = self.get_raw_token(header)
        if raw_token is None:
            return None

        try:
            validated_token: SequenceToken = self.get_validated_token(raw_token)
        except InvalidToken as ae:
            raise ae

        try:
            return self.get_user(validated_token), validated_token
        except InvalidToken as ie:
            raise ie
        except AuthenticationFailed as ae:
            raise ae

    def authenticate_header(self, request: Request) -> str:
        return '{} realm="{}"'.format(
            AUTH_HEADER_TYPES[0],
            self.www_authenticate_realm,
        )

    def get_header(self, request) -> bytes:
        """
        Extracts the header containing the JSON web token from the given
        request.
        """
        header: bytes | str = request.META.get(api_settings.AUTH_HEADER_NAME)

        if isinstance(header, str):
            # Work around django test client oddness
            header: bytes = header.encode(HTTP_HEADER_ENCODING)

        return header

    def get_raw_token(self, header: bytes) -> bytes | None | NoReturn:
        """
        Extracts an unvalidated JSON web token from the given "Authorization"
        header value.
        """
        parts: list[bytes] = header.split()

        if len(parts) == 0:
            # Empty AUTHORIZATION header sent
            return None

        if parts[0] not in AUTH_HEADER_TYPE_BYTES:
            # Assume the header does not contain a JSON web token
            return None

        if len(parts) != 2:
            raise AuthenticationFailed(
                _("Authorization header must contain two space-delimited values"),
                code="bad_authorization_header",
            )

        return parts[1]

    def get_validated_token(self, raw_token: bytes) -> Token | NoReturn:
        """
        Validates an encoded JSON web token and returns a validated token
        wrapper object.
        """

        messages: DetailedMessage = []
        for AuthToken in api_settings.AUTH_TOKEN_CLASSES:
            try:
                return AuthToken(raw_token)
            except TokenError as e:
                messages.append(
                    {
                        "token_class": AuthToken.__name__,
                        "token_type": AuthToken.token_type,
                        "message": e.args[0],
                    }
                )

        raise InvalidToken(
            {
                "detail": _("Given token not valid for any token type"),
                "messages": messages,
            }
        )

    def get_user(self, validated_token: SequenceToken) -> CallableUser | NoReturn:
        """
        Attempts to find and return a user using the given validated token.
        """
        from apps.user_portal.models import CallableUser
        try:
            user_id: str | int = validated_token[api_settings.USER_ID_CLAIM]
        except KeyError:
            raise InvalidToken(_("Token contained no recognizable user identification"))

        try:
            user: CallableUser = self.user_model.objects.get(**{api_settings.USER_ID_FIELD: user_id})
            user_details: ChildUser = get_user_model().objects.get_subclass(email=user.email)
        except self.user_model.DoesNotExist:
            raise AuthenticationFailed(_("User not found"), code="user_not_found")

        if not user_details.is_active:
            raise AuthenticationFailed(_("User is inactive"), code="user_inactive")

        return user


class SimpleJWTTokenUserScheme(SimpleJWTScheme):
    target_class = CustomJWTAuthentication
