import environ
from django.core.mail import EmailMessage

from config import settings


def send_email(data):
    try:
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            from_email=settings.EMAIL_HOST_USER,
            to=[data['to_email']]
        )
        email.send()
        return True
    except TypeError as e:
        return False
