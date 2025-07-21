# accounts/management/commands/clean_unverified_users.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.contrib.auth import get_user_model
from users.models import OTP, User
from datetime import timedelta


class Command(BaseCommand):
    help = 'Delete unverified users whose OTPs have expired beyond a grace period.'

    def handle(self, *args, **options):
        # User = get_user_model()
        now = timezone.now()
        grace_period = timedelta(minutes=5)

        expired_otps = OTP.objects.filter(
            purpose="register",
            expires_at__lt=now - grace_period
        ).values_list('email', flat=True)

        users_to_delete = User.objects.filter(
            is_verified=False,
            email__in=expired_otps
        )

        count = users_to_delete.count()
        users_to_delete.delete()

        self.stdout.write(self.style.SUCCESS(f"Deleted {count} unverified user(s)."))
