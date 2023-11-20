# Download the helper library from https://www.twilio.com/docs/python/install
import base64

import pyotp
from django.conf import settings
from environ import Env
from pyotp import TOTP
from twilio.rest import Client
from twilio.rest.chat.v2.service.channel.message import MessageInstance

from apps.user_portal.models import CallableUser


# Set environment variables for your credentials
# Read more at http://twil.io/secure
# class VerificationMessageHandler:
#   def __init__(self):
#     self.account_sid =
#     self.auth_token = auth_token
#     self.verify_sid = verify_sid
#     self.verified_number = verified_number
#
# client = Client(account_sid, auth_token)
#
# verification = client.verify.v2.services(verify_sid) \
#   .verifications \
#   .create(to=verified_number, channel="sms")
# print(verification.status)
#
# otp_code = input("Please enter the OTP:")
#
# verification_check = client.verify.v2.services(verify_sid) \
#   .verification_checks \
#   .create(to=verified_number, code=otp_code)
# print(verification_check.status)


class MessageHandler:
    def __init__(self, phone_number: int, otp: str) -> None:
        self.phone_number = phone_number
        self.otp = otp

    def send_otp_via_message(self) -> MessageInstance:
        client: Client = Client(settings.ACCOUNT_SID, settings.AUTH_TOKEN)
        message: MessageInstance = client.messages.create(body=f'your otp is:{self.otp}',
                                                          from_=f"{settings.TWILIO_PHONE_NUMBER}",
                                                          to=f"{settings.COUNTRY_CODE}{self.phone_number}")
        return message


def generate_otp_object(user: CallableUser) -> TOTP:
    env = Env()
    totp: TOTP = pyotp.TOTP(
        s=base64.b32encode(bytes(user.email, 'utf-8')).decode('utf-8'),
        digits=int(env('OTP_DIGITS')),
        interval=int(env('OTP_EXPIRY_TIME')),
        name=str(user.email),
        issuer=str(env('OTP_ISSUER')),
    )
    return totp
