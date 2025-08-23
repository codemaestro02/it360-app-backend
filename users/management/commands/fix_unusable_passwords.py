# users/management/commands/fix_unusable_passwords.py
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.conf import settings
from django.core.mail import send_mail
from django.db import transaction

import secrets
import string

User = get_user_model()


def generate_password(length: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


class Command(BaseCommand):
    help = (
        "Finds users with unusable passwords and assigns a temporary password.\n"
        "By default, prints the changes. Use --email-users to send notifications."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would change without saving.'
        )
        parser.add_argument(
            '--password',
            type=str,
            help='Set this exact temporary password for all affected users.'
        )
        parser.add_argument(
            '--length',
            type=int,
            default=12,
            help='Length for generated passwords (ignored if --password is provided). Default: 12'
        )
        parser.add_argument(
            '--email-users',
            action='store_true',
            help='Email affected users their temporary password.'
        )
        parser.add_argument(
            '--emails',
            type=str,
            help='Comma-separated list of user emails to restrict the operation.'
        )
        parser.add_argument(
            '--limit',
            type=int,
            default=None,
            help='Process at most this many users.'
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        fixed_password = options.get('password')
        length = options['length']
        email_users = options['email_users']
        limit = options['limit']

        email_filter = None
        if options.get('emails'):
            email_filter = [e.strip() for e in options['emails'].split(',') if e.strip()]

        qs = User.objects.all()
        if email_filter:
            qs = qs.filter(email__in=email_filter)

        # Only users with unusable passwords
        affected = [u for u in qs if not u.has_usable_password()]
        if limit is not None:
            affected = affected[:limit]

        if not affected:
            self.stdout.write(self.style.SUCCESS('No users with unusable passwords found.'))
            return

        plan = []
        for user in affected:
            temp_pw = fixed_password or generate_password(length)
            plan.append((user, temp_pw))

        self.stdout.write(f"Users to repair: {len(plan)}")
        for user, temp_pw in plan:
            self.stdout.write(f" - {user.email}: {temp_pw}")

        if dry_run:
            self.stdout.write(self.style.WARNING('Dry run: no changes were saved.'))
            return

        with transaction.atomic():
            for user, temp_pw in plan:
                user.set_password(temp_pw)
                user.save(update_fields=['password'])

        self.stdout.write(self.style.SUCCESS(f"Updated {len(plan)} user(s)."))

        if email_users:
            from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', None) or getattr(settings, 'EMAIL_HOST_USER', None)
            if not from_email:
                raise CommandError('No DEFAULT_FROM_EMAIL or EMAIL_HOST_USER configured for sending emails.')

            sent = 0
            for user, temp_pw in plan:
                subject = "Your temporary password"
                message = (
                    f"Hello,\n\n"
                    f"We’ve set a temporary password for your account: {temp_pw}\n\n"
                    f"Please log in and change your password immediately from your profile or settings page.\n\n"
                    f"If you did not request this change, contact support.\n"
                )
                try:
                    send_mail(subject, message, from_email, [user.email], fail_silently=False)
                    sent += 1
                except Exception as e:
                    self.stderr.write(self.style.ERROR(f"Failed to email {user.email}: {e}"))

            self.stdout.write(self.style.SUCCESS(f"Emailed {sent}/{len(plan)} user(s)."))