import uuid
from datetime import timedelta
from threading import Timer

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from django.core.validators import RegexValidator

from shared.models import GenericBaseModel

# Create your models here.

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, role=None, **extra_fields):
        if not email:
            raise ValueError("Users must have an email address")
        email = self.normalize_email(email)
        if role == "instructor":
            extra_fields.setdefault("is_staff", True)
        elif role == "admin":
            extra_fields.setdefault("is_staff", True)
            extra_fields.setdefault("is_superuser", True)
        user = self.model(email=email, role=role, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, password, role="admin", **extra_fields)


class StudentManager(models.Manager):
    """
    Custom manager for a Student model to filter students.
    """
    def get_queryset(self):
        return super().get_queryset().filter(role='student')

class SponsorManager(models.Manager):
    """
    Custom manager for a Sponsor model to filter sponsors.
    """
    def get_queryset(self):
        return super().get_queryset().filter(role='sponsor')

class InstructorManager(models.Manager):
    """
    Custom manager for an Instructor model to filter instructors.
    """
    def get_queryset(self):
        return super().get_queryset().filter(role='instructor')

class AdminManager(models.Manager):
    """
    Custom manager for an Admin model to filter administrators.
    """
    def get_queryset(self):
        return super().get_queryset().filter(role='admin')


class TemporaryUserManager(models.Manager):
    """
    Custom manager for a Temporary User model to filter temporary users.
    """
    def get_queryset(self):
        return super().get_queryset().filter(role='temp_user')


class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (
        ("student", "Student"),
        ("instructor", "Instructor"),
        ("sponsor", "Sponsor"),
        ("admin", "Admin"),
        ("temp_user", "Temporary User"),
    )
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for the user."
    )
    email = models.EmailField(unique=True)
    use_email_as_user_ID = models.BooleanField(default=False, help_text="Use email as username for login.")
    first_name = models.CharField(max_length=50, blank=True, null=True, help_text="First name of the user.")
    last_name = models.CharField(max_length=50, blank=True, null=True, help_text="Last name of the user.")
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='temp_user',
        help_text="Role of the user in the system."
    )
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserManager()
    user_students = StudentManager()
    user_sponsors = SponsorManager()
    user_instructors = InstructorManager()
    user_admins = AdminManager()
    user_temporary_users = TemporaryUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

    @property
    def full_name(self):
        """
        Returns the full name of the user.
        :return: Full name as a string.
        """
        return f"{self.first_name} {self.last_name}".strip()


class OTP(models.Model):
    PURPOSE_CHOICES = (
        ("register", "Register"),
        ("reset_password", "Reset Password"),
    )

    email = models.EmailField()
    code = models.CharField(max_length=5, validators=[RegexValidator(r"^\d{5}$")])
    purpose = models.CharField(max_length=20, choices=PURPOSE_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_expired(self):
        return timezone.now() > self.expires_at

    def __str__(self):
        return f"{self.email} - {self.purpose}"


class Student(models.Model):
    """
    Student model that inherits from User.
    This model is used to represent students in the application.
    """
    GENDER_CHOICES = (
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other'),
    )
    user = models.OneToOneField(
        'User',
        on_delete=models.CASCADE,
        related_name="student_profile",
        limit_choices_to={'role': 'student'}
    )
    linked_sponsor = models.ForeignKey(
        'Sponsor',
        blank=True,
        null=True,
        related_name='linked_wards',
        on_delete=models.SET_NULL
    )
    phone_number = models.CharField(max_length=15, blank=True, null=True, help_text="Phone number of the student.")
    gender = models.CharField(
        max_length=10,
        choices=GENDER_CHOICES,
        blank=True, null=True,
        help_text="Gender of the student."
    )
    date_of_birth = models.DateField(blank=True, null=True, help_text="Date of birth of the student.")
    nationality = models.CharField(max_length=50, blank=True, null=True)
    location = models.CharField(max_length=100, blank=True, null=True, help_text="Location of the student.")
    profile_picture = models.TextField(blank=True, null=True, help_text="Profile picture of the student.")
    current_school = models.CharField(max_length=100, blank=True, null=True, help_text="Current school of the student.")
    current_grade = models.CharField(max_length=50, blank=True, null=True, help_text="Current grade of the student.")

    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name} ({self.user.user_ID})"


class Sponsor(models.Model):
    """
    Sponsor model that inherits from User.
    This model is used to represent sponsors in the application.
    """
    GENDER_CHOICES = (
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other'),
    )
    user = models.OneToOneField(
        'User',
        on_delete=models.CASCADE,
        related_name="sponsor_profile",
        limit_choices_to={'role': 'sponsor'}
    )
    gender = models.CharField(choices=GENDER_CHOICES, max_length=10, blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True, help_text="Phone number of the sponsor.")
    address = models.TextField(blank=True, null=True, help_text="Address of the sponsor.")
    profile_picture = models.TextField(blank=True, null=True, help_text="Profile picture of the sponsor.")

    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name} ({self.user.user_ID})"


class Instructor(models.Model):
    """
    Instructor model that inherits from User.
    This model is used to represent instructors in the application.
    """
    GENDER_CHOICES = (
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other'),
    )
    user = models.OneToOneField(
        'User',
        on_delete=models.CASCADE,
        related_name="instructor_profile",
        limit_choices_to={'role': 'instructor'}
    )
    gender = models.CharField(choices=GENDER_CHOICES, max_length=10, blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True, help_text="Phone number of the instructor.")
    address = models.TextField(blank=True, null=True, help_text="Address of the instructor.")
    bio = models.TextField(blank=True, null=True, help_text="Short biography of the instructor.")
    profile_picture = models.TextField(blank=True, null=True, help_text="Profile picture of the instructor.")

    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name} ({self.user.user_ID})"
    

class Certification(models.Model):
    instructor = models.ForeignKey(
        'Instructor',
        on_delete=models.CASCADE,
        related_name='certifications'
    )
    name = models.CharField(max_length=255, help_text="Name of the certification.")
    issuer = models.CharField(
        max_length=255,
        help_text="Issuer of the certification.",
        blank=True,
        null=True
    )
    date_awarded = models.DateField(null=True, blank=True)
    expires_at = models.DateField(null=True, blank=True, help_text="Expiration date of the certification.")


class Admin(models.Model):
    """
    Admin model that inherits from User.
    This model is used to represent administrators in the application.
    """
    GENDER_CHOICES = (
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other'),
    )
    user = models.OneToOneField(
        'User',
        on_delete=models.CASCADE,
        related_name="admin_profile",
        limit_choices_to={'role': 'admin'}
    )
    gender = models.CharField(choices=GENDER_CHOICES, max_length=10, blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True, help_text="Phone number of the admin.")
    address = models.TextField(blank=True, null=True, help_text="Address of the admin.")
    profile_picture = models.TextField(blank=True, null=True, help_text="Profile picture of the admin.")

    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name} ({self.user.user_ID})"

@receiver(post_save, sender=OTP)
def cleanup_unverified_users(sender, instance, created, **kwargs):
    if not created:
        return

    if instance.purpose == "register":
        expire_time = instance.expires_at + timedelta(minutes=5)

        def delete_unverified():
            expired_users = User.objects.filter(
                email=instance.email,
                is_verified=False,
                date_joined__lt=expire_time
            )
            for user in expired_users:
                user.delete()

        delay_seconds = (expire_time - timezone.now()).total_seconds()
        Timer(delay_seconds, delete_unverified).start()