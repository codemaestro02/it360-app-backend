import uuid
import random
import os
from datetime import timedelta
from dotenv import load_dotenv

from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings

from rest_framework import serializers
from rest_framework.fields import empty
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .models import (User, Student, Sponsor, Admin,
                     Instructor, Certification, OTP)
from .utils import get_tokens_for_user, convert_to_base64, send_otp_email

# Load environment variables from .env file
load_dotenv()

def validate_password_length(value):
    if len(value) < 8:
        raise serializers.ValidationError("Password must be at least 8 characters long.")
    return value


def validate_email(value):
    if User.objects.filter(email=value).exists():
        raise serializers.ValidationError("This email is already in use.")
    return value


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'user_ID', 'email', 'first_name', 'last_name', 'role', 'is_verified', 'is_active']
        read_only_fields = ['id', 'user_ID', 'is_verified', 'is_active']

    def validate_email(self, value):
        return validate_email(value)

    def validate_role(self, value):
        if value not in dict(User.ROLE_CHOICES).keys():
            raise serializers.ValidationError(f"Invalid role. Choose from {', '.join(dict(User.ROLE_CHOICES).keys())}.")
        return value


class RegistrationSerializer(serializers.ModelSerializer):
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES, required=False)
    email = serializers.EmailField(required=True)
    user_ID = serializers.CharField(read_only=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    password2 = serializers.CharField(write_only=True, required=True)
    id = serializers.IntegerField(read_only=True)

    class Meta:
        model = User
        fields = [
            'id', 'user_ID', 'email', 'password', 'password2', 'first_name', 'last_name',
            'role', 'use_email_as_user_ID'
        ]
        extra_kwargs = {
            'password': {'write_only': True, 'required': True},
            'password2': {'write_only': True, 'required': True},
            'use_email_as_user_ID': {'required': False, 'write_only': True},
        }
        read_only_fields = ['id', 'user_ID']

    def validate(self, attrs):
        if 'email' in attrs:
            attrs['email'] = validate_email(attrs['email'])
        if 'password' in attrs:
            attrs['password'] = validate_password_length(attrs['password'])
        if 'password2' in attrs:
            attrs['password2'] = validate_password_length(attrs['password2'])
        if 'password2' in attrs and 'password' not in attrs:
            raise serializers.ValidationError("Password2 is provided but password is missing.")
        if 'password' not in attrs and 'password2' not in attrs:
            raise serializers.ValidationError("Password is required.")
        if 'password' in attrs and 'password2' in attrs:
            if attrs['password'] != attrs['password2']:
                raise serializers.ValidationError("Passwords do not match.")
        if 'role' in attrs and attrs['role'] not in dict(User.ROLE_CHOICES).keys():
            raise serializers.ValidationError(f"Invalid role. Choose from {', '.join(dict(User.ROLE_CHOICES).keys())}.")
        # Prevent updating use_email_as_username for existing users
        if self.instance and 'use_email_as_user_ID' in attrs:
            raise serializers.ValidationError("use_email_as_user_ID cannot be updated after registration.")
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        password = validated_data.pop('password')
        role = validated_data.get('role', 'temp_user')
        user = User.objects.create_user(
            **validated_data
        )
        try:
            user_class = {
                'student': Student,
                'sponsor': Sponsor,
                'admin': Admin,
                'instructor': Instructor
            }.get(role)
            if user_class:
                user_class.objects.create(user=user)
            else:
                raise serializers.ValidationError(f"Invalid role: {role}.")
            code = "12345" if os.getenv('OTP_NOT_IN_PROD', 'True').lower() == "true" else f"{random.randint(10000, 99999)}"
            otp_token_lifetime = int(os.getenv('OTP_LIFETIME', 10))  # Default to 10 minutes if not set
            expiry = timezone.now() + timedelta(seconds=otp_token_lifetime)

            OTP.objects.update_or_create(
                email=user.email,
                code=code,
                purpose='register',
                expires_at=expiry
            )

            # TODO: send email with OTP
            send_otp_email(user.email, code, 'register')
            return user
        except Exception as e:
            user.delete()
            raise serializers.ValidationError(f"Error creating user profile: {str(e)}")


class RegistrationLoginResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    user = UserSerializer()
    jwt_token = serializers.DictField(
        default={
            'access': 'access_token_placeholder',
            'refresh': 'refresh_token_placeholder',
            'expires_in': 3600  # Default to 1 hour
        }
    )


class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=5)

    def validate(self, attrs):
        email = attrs['email']
        code = attrs['code']

        try:
            otp = OTP.objects.filter(email=email, code=code, purpose='register').last()
            if not otp:
                raise serializers.ValidationError("Invalid OTP code.")
            if otp.is_expired():
                otp.delete()  # Clean up expired OTP
                raise serializers.ValidationError("OTP has expired.")
        except OTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP.")



        user = User.objects.filter(email=email).first()
        if not user:
            raise serializers.ValidationError("User not found.")

        user.is_verified = True
        user.save()

        return attrs

    def create(self, validated_data):
        email = validated_data['email']
        code = validated_data['code']
        user = User.objects.get(email=email)
        if not user:
            raise serializers.ValidationError("User not found.")
        otp = OTP.objects.filter(email=email, code=code, purpose='register').last()
        if not otp or otp.is_expired():
            otp.delete()  # Clean up expired OTP
            raise serializers.ValidationError("Invalid or expired OTP.")

        user.is_verified = True
        user.save()
        return user




class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True)
    jwt_token = serializers.DictField(read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password']
        read_only_fields = ['jwt_token']

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if not email or not password:
            raise serializers.ValidationError("Both email and password are required.")

        user = authenticate(email=email, password=password)
        if not user:
            user = User.objects.filter(email=email).first()

        if not user:
            raise serializers.ValidationError("Invalid credentials.")

        if not user.is_verified:
            raise serializers.ValidationError("Account not verified.")

        if not user.is_active:
            raise serializers.ValidationError("Account is inactive.")

        jwt_token = get_tokens_for_user(user)
        attrs['jwt_token'] = jwt_token
        attrs['user'] = user
        return attrs

    def create(self, validated_data):
        user = validated_data['user']
        jwt_token = validated_data['jwt_token']
        return {
            'message': "Login successful",
            'user': UserSerializer(user).data,
            'jwt_token': jwt_token
        }


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def __init__(self, instance=None, data=empty, **kwargs):
        super().__init__(instance, data, **kwargs)
        self.token = None

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            token = RefreshToken(self.token)
            token.blacklist()
        except TokenError:
            raise serializers.ValidationError("Token is invalid or expired.")


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, attrs):
        email = attrs.get('email')
        if not User.objects.filter(email=email, is_verified=True).exists():
            raise serializers.ValidationError("No user found with this email.")
        return attrs

    def save(self):
        email = self.validated_data['email']
        code = "12345" if os.getenv('OTP_NOT_IN_PROD', 'True').lower() == "true" else f"{random.randint(10000, 99999)}"
        otp_token_lifetime = int(os.getenv('OTP_LIFETIME', 10))  # Default to 10 minutes if not set
        expiry = timezone.now() + timedelta(seconds=otp_token_lifetime)
        OTP.objects.create(
            email=email,
            code=code,
            purpose='reset_password',
            expires_at=expiry
        )
        # TODO: send OTP email
        send_otp_email(email, code, 'forgot_password')


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=5)
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")

        try:
            otp = OTP.objects.get(
                email=attrs['email'],
                code=attrs['code'],
                purpose='reset_password'
            )
        except OTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP.")

        if otp.is_expired():
            raise serializers.ValidationError("OTP expired.")

        return attrs

    def save(self):
        user = User.objects.get(email=self.validated_data['email'])
        user.set_password(self.validated_data['new_password'])
        user.save()


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        user = self.context['request'].user

        if not user.check_password(attrs['current_password']):
            raise serializers.ValidationError("Current password is incorrect.")

        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")

        validate_password(attrs['new_password'], user)
        return attrs

    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()


class StudentProfileSerializer(serializers.ModelSerializer):
    profile_picture_media = serializers.ImageField(
        allow_empty_file=True,
        allow_null=True,
        required=False,
        write_only=True,
        help_text="Upload an image file."
    )
    # user = serializers.PrimaryKeyRelatedField(read_only=True)
    linked_sponsor = serializers.PrimaryKeyRelatedField(
        queryset=Sponsor.objects.all(),
        required=False,
        allow_null=True,
        help_text="Sponsor linked to the student profile."
    )
    user_details = UserSerializer(source='user', read_only=True)

    class Meta:
        model = Student
        fields = ['id', 'gender', 'date_of_birth', 'phone_number', 'nationality',
                  'current_school', 'current_grade', 'location', 'profile_picture_media',
                  'linked_sponsor', 'user_details']
        read_only_fields = ['id', 'user', 'user_details', 'profile_picture']
        extra_kwargs = {
            'linked_sponsor': {'required': False, 'allow_null': True},
            'user_details': {'read_only': True},
            'profile_picture_media': {'required': False, 'allow_null': True, 'write_only': True},
        }

    def validate_image(self, value):
        if value and not value.name.lower().endswith(('.png', '.jpg', '.jpeg')):
            raise serializers.ValidationError("Unsupported file format. Only PNG, JPG, and JPEG are allowed.")
        return value

    def validate(self, attrs):
        if 'profile_picture_media' in attrs:
            media = self.validate_image(attrs.get('profile_picture_media'))
            attrs['profile_picture'] = convert_to_base64(media)

        if not self.instance and not attrs.get('user'):
            raise serializers.ValidationError("User is required to create a student profile.")
        return attrs

    def create(self, validated_data):
        user = validated_data.pop('user')
        validated_data.pop('profile_picture_media')
        student = Student.objects.create(user=user, **validated_data)
        return student


class SponsorProfileSerializer(serializers.ModelSerializer):
    profile_picture_media = serializers.ImageField(
        allow_empty_file=True,
        allow_null=True,
        required=False,
        write_only=True,
        help_text="Upload an image file."
    )
    user = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        required=False,
        help_text="User associated with the sponsor profile."
    )
    user_details = UserSerializer(source='user', read_only=True)

    class Meta:
        model = Sponsor
        fields = ['id', 'user', 'gender', 'phone_number', 'address', 'profile_picture_media', 'user_details']
        read_only_fields = ['id', 'user', 'profile_picture']

    def validate_image(self, value):
        if value and not value.name.lower().endswith(('.png', '.jpg', '.jpeg')):
            raise serializers.ValidationError("Unsupported file format. Only PNG, JPG, and JPEG are allowed.")
        return value

    def validate(self, attrs):
        if 'profile_picture_media' in attrs:
            media = self.validate_image(attrs.get('profile_picture_media'))
            attrs['profile_picture'] = convert_to_base64(media)

        if not self.instance and not attrs.get('user'):
            raise serializers.ValidationError("User is required to create a sponsor profile.")
        return attrs

    def create(self, validated_data):
        user = validated_data.pop('user')
        validated_data.pop('profile_picture_media')
        sponsor = Sponsor.objects.create(user=user, **validated_data)
        return sponsor


class CertificationSerializer(serializers.ModelSerializer):
    instructor = serializers.PrimaryKeyRelatedField(
        read_only=True,
    )

    class Meta:
        model = Certification
        fields = ['id', 'name', 'issuer', 'instructor', 'date_awarded', 'expires_at']


class InstructorProfileSerializer(serializers.ModelSerializer):
    profile_picture_media = serializers.ImageField(
        allow_empty_file=True,
        allow_null=True,
        required=False,
        write_only=True,
        help_text="Upload an image file."
    )
    user = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        required=False,
        help_text="User associated with the instructor profile."
    )
    user_details = UserSerializer(source='user', read_only=True)
    certifications = CertificationSerializer(many=True, required=False, allow_null=True, allow_empty=True)

    class Meta:
        model = Instructor
        fields = ['id', 'user', 'phone_number', 'address', 'profile_picture_media', 'user_details',
                  'certifications']
        read_only_fields = ['id', 'user', 'profile_picture']

    def validate_image(self, value):
        if value and not value.name.lower().endswith(('.png', '.jpg', '.jpeg')):
            raise serializers.ValidationError("Unsupported file format. Only PNG, JPG, and JPEG are allowed.")
        return value

    def validate(self, attrs):
        if 'profile_picture_media' in attrs:
            media = self.validate_image(attrs.get('profile_picture_media'))
            attrs['profile_picture'] = convert_to_base64(media)

        if not self.instance and not attrs.get('user'):
            raise serializers.ValidationError("User is required to create an instructor profile.")
        return attrs

    def create(self, validated_data):
        user = validated_data.pop('user')
        validated_data.pop('profile_picture_media')
        certifications_data = validated_data.pop('certifications', [])
        instructor = Instructor.objects.create(user=user, **validated_data)
        if len(certifications_data) > 0:
            Certification.objects.bulk_create([
                Certification(instructor=instructor, **cert_data) for cert_data in certifications_data
            ])
        return instructor

    def update(self, instance, validated_data):
        certifications_data = validated_data.pop('certifications', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if certifications_data is not None:
            # update certifications by deleting those not in the sent data (PUT)
            # existing_certifications = [cert.id for cert in instance.certifications.all()]
            # sent_certifications = [cert['id'] for cert in certifications_data if 'id' in cert]
            # # Delete certifications that are not in the sent data
            # for cert_id in set(existing_certifications) - set(sent_certifications):
            #     instance.certifications.filter(id=cert_id).delete()

            # Works well for PATCH requests
            for cert in certifications_data:
                if 'id' in cert:
                    # Update existing certification
                    certification = instance.certifications.get(id=cert['id'])
                    for key, value in cert.items():
                        setattr(certification, key, value)
                    certification.save()
                else:
                    # Create new certification
                    Certification.objects.create(instructor=instance, **cert)
        return instance


# GET Serializer
class AdminProfileRetrieveSerializer(serializers.ModelSerializer):
    user_details = UserSerializer(source='user', read_only=True)

    class Meta:
        model = Admin
        fields = "__all__"
        read_only_fields = ['id', 'user', 'profile_picture', 'user_details']

# POST Serializer (Create)
class AdminProfileCreateSerializer(serializers.ModelSerializer):
    profile_picture_media = serializers.ImageField(
        allow_empty_file=True,
        allow_null=True,
        required=False,
        write_only=True,
        help_text="Upload an image file."
    )
    user = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        help_text="User associated with the admin profile."
    )

    class Meta:
        model = Admin
        exclude = ['profile_picture']
        extra_kwargs = {
            'profile_picture_media': {'required': False, 'allow_null': True, 'write_only': True},
        }

    def validate_image(self, value):
        if value and not value.name.lower().endswith(('.png', '.jpg', '.jpeg')):
            raise serializers.ValidationError("Unsupported file format. Only PNG, JPG, and JPEG are allowed.")
        return value

    def validate(self, attrs):
        if 'profile_picture_media' in attrs:
            media = self.validate_image(attrs.get('profile_picture_media'))
            attrs['profile_picture'] = convert_to_base64(media)
            attrs.pop('profile_picture_media', None)
        if not attrs.get('user'):
            raise serializers.ValidationError("User is required to create an admin profile.")
        return attrs

    def create(self, validated_data):
        user = validated_data.pop('user')
        validated_data.pop('profile_picture_media', None)
        admin = Admin.objects.create(user=user, **validated_data)
        return admin

# PUT/PATCH Serializer (Update)
class AdminProfileUpdateSerializer(serializers.ModelSerializer):
    profile_picture_media = serializers.ImageField(
        allow_empty_file=True,
        allow_null=True,
        required=False,
        write_only=True,
        help_text="Upload an image file."
    )

    class Meta:
        model = Admin
        exclude = ['profile_picture', 'user']
        extra_kwargs = {
            'profile_picture_media': {'required': False, 'allow_null': True, 'write_only': True},
        }

    def validate_image(self, value):
        if value and not value.name.lower().endswith(('.png', '.jpg', '.jpeg')):
            raise serializers.ValidationError("Unsupported file format. Only PNG, JPG, and JPEG are allowed.")
        return value

    def validate(self, attrs):
        if 'profile_picture_media' in attrs:
            media = self.validate_image(attrs.get('profile_picture_media'))
            attrs['profile_picture'] = convert_to_base64(media)
            attrs.pop('profile_picture_media', None)
        return attrs

    def update(self, instance, validated_data):
        validated_data.pop('profile_picture_media', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance

# DELETE Serializer (Optional, usually not needed, but for completeness)
class AdminProfileDeleteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Admin
        fields = ['id']