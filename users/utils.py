import base64
import mimetypes

from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from rest_framework.exceptions import APIException
from rest_framework_simplejwt.tokens import RefreshToken


def get_tokens_for_user(user):
    """
    Generate JWT tokens for the given user.

    Args:
        user: The user instance for whom to generate tokens.

    Returns:
        A dictionary containing access and refresh tokens.
    """
    refresh = RefreshToken.for_user(user)
    token_lifetime = refresh.lifetime

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
        'expires_in': int(token_lifetime.total_seconds()),
    }


def convert_to_base64(file, max_size):
    mime_type, _ = mimetypes.guess_type(file.name)
    if mime_type not in ['image/png', 'image/jpeg', 'image/png']:
        raise APIException(detail="Invalid file type, Only JPEG, JPG and PNG files are allowed")

    if file.size > max_size:
        raise APIException(detail=f"File size exceeds the max limit of {max_size // (1024 * 1014)} MB")

    image_data = file.read()
    return base64.b64encode(image_data).decode("utf-8")


def send_otp_email(email, code, purpose):
    if purpose == 'register':
        subject = 'Verify your account'
        template_name = 'emails/register_otp.html'
    elif purpose == 'reset_password':
        subject = 'Reset your password'
        template_name = 'emails/reset_password_otp.html'
    else:
        subject = 'Your OTP Code'
        template_name = 'emails/generic_otp.html'

    context = {
        'otp_code': code,
        'support_email': settings.DEFAULT_FROM_EMAIL
    }

    html_message = render_to_string(template_name, context)
    plain_message = strip_tags(html_message)

    send_mail(
        subject,
        plain_message,
        settings.DEFAULT_FROM_EMAIL,
        [email],
        html_message=html_message,
        fail_silently=False,
    )