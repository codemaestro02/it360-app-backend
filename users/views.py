import uuid

from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import viewsets, mixins, status, permissions, pagination
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.filters import SearchFilter
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .serializers import (
    RegistrationSerializer, VerifyOTPSerializer, LoginSerializer,
    LogoutSerializer, ForgotPasswordSerializer, ResetPasswordSerializer,
    ChangePasswordSerializer, UserSerializer
)

# for Admin
from .models import Admin
from .serializers import (AdminProfileSerializer)

# for students
from .models import Student
from .serializers import (StudentProfileSerializer)

# for sponsors
from .models import Sponsor
from .serializers import (SponsorProfileSerializer, SponsorLinkStudentSerializer)

# for instructors
from .models import Instructor, Certification
from .serializers import (InstructorProfileSerializer, CertificationSerializer)

import shared.permissions as app_permissions
from .utils import get_tokens_for_user


class RetrieveProfileMixin:
    """
    Retrieve a user profile.
    """
    @action(methods=['get'], detail=False, url_path='get-profile')
    def get_profile(self, request, *args, **kwargs):
        user = request.user
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class UpdateProfileMixin:
    """
    Update a user profile.
    """
    @action(methods=['put', 'patch'], detail=False, url_path='update-profile')
    def update_profile(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, '_prefetched_objects_cache', None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}

        return Response({
            'message': 'Profile updated successfully',
            'user': serializer.data
        }, status=status.HTTP_200_OK)
    
    def perform_update(self, serializer):
        serializer.save()


class StudentProfileViewSet(RetrieveProfileMixin, UpdateProfileMixin, viewsets.GenericViewSet):
    """
    View for handling user profile operations.
    This view allows users to retrieve and update their profile information.
    """
    tag_name = "Student Profile"
    serializer_class = StudentProfileSerializer
    permission_classes = [app_permissions.IsStudent]

    def get_object(self):
        """
        Retrieve the user profile of the currently authenticated student.
        :return:
        """
        user_id = self.request.user.id
        try:
            return self.serializer_class.Meta.model.objects.get(user_id=user_id)
        except self.serializer_class.Meta.model.DoesNotExist:
            raise ValidationError({'detail': 'User profile not found.'})

    def get_queryset(self):
        """
        Return the queryset for the user profile.
        This queryset is filtered to return only the authenticated user's profile.
        :return:
        """
        return self.serializer_class.Meta.model.objects.filter(user_id=self.request.user.id)


class SponsorProfileViewSet(RetrieveProfileMixin, UpdateProfileMixin, viewsets.GenericViewSet):
    """
    View for handling sponsor profile operations.
    This view allows sponsors to retrieve and update their profile information.
    """
    tag_name = "Sponsor Profile"
    serializer_class = SponsorProfileSerializer  # Assuming the same serializer is used for sponsors
    permission_classes = [app_permissions.IsSponsor]

    def get_object(self):
        """
        Retrieve the user profile of the currently authenticated sponsor.
        :return:
        """
        user_id = self.request.user.id
        try:
            return self.serializer_class.Meta.model.objects.get(user_id=user_id)
        except self.serializer_class.Meta.model.DoesNotExist:
            raise ValidationError({'detail': 'User profile not found.'})

    def get_queryset(self):
        """
        Return the queryset for the user profile.
        This queryset is filtered to return only the authenticated user's profile.
        :return:
        """
        return self.serializer_class.Meta.model.objects.filter(user_id=self.request.user.id)

    @action(methods=['get'], detail=False, url_path='get-linked-wards')
    def get_linked_wards(self, request):
        sponsor = self.get_object()
        linked_wards = sponsor.linked_wards.all()
        if linked_wards:
            return Response(
                StudentProfileSerializer(linked_wards, many=True).data,
                status=status.HTTP_200_OK
            )
        return Response(
            {'detail': 'No linked wards found.'},
            status=status.HTTP_404_NOT_FOUND
        )


class SponsorLinkStudentViewSet(viewsets.GenericViewSet):
    """
    Link or Unlink a student to the current authenticated sponsor's profile.
    Use either student_id or student email but not both.
    """
    tag_name = "Sponsor Student Link"
    serializer_class = SponsorLinkStudentSerializer
    permission_classes = [app_permissions.IsSponsor]

    @action(methods=['post'], detail=False, url_path='link-student')
    def link_student(self, request, pk=None):
        user = self.request.user
        # if not user.is_authenticated or user.role != 'sponsor':
        #     return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        student_id = serializer.validated_data.get('student_id')
        try:
            student = Student.objects.get(user_id=student_id)
            student.linked_sponsor = Sponsor.objects.get(user_id=user.id)
            student.save()
            return Response({'detail': 'Student linked successfully.'}, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response({'detail': 'Student not found.'}, status=status.HTTP_404_NOT_FOUND)

    @action(methods=['post'], detail=False, url_path='unlink-student')
    def unlink_student(self, request, pk=None):
        user = self.request.user
        if not user.is_authenticated or user.role != 'sponsor':
            return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        student_id = serializer.validated_data.get('student_id')
        try:
            student = Student.objects.get(user_id=student_id)
            student.linked_sponsor = None
            student.save()
            return Response({'detail': 'Student unlinked successfully.'}, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response({'detail': 'Student not found.'}, status=status.HTTP_404_NOT_FOUND)


class CertificationViewSet(viewsets.ModelViewSet):
    """
    Used to create certifications for instructors

    params: instructor_pk
    function: This means the instructor user_id
    """
    tag_name = 'Instructor Certification'
    serializer_class = CertificationSerializer
    filter_backends = [SearchFilter]
    pagination_class = pagination.PageNumberPagination
    search_fields = ['name', 'issuer']
    permission_classes = [app_permissions.IsInstructor | app_permissions.IsAdmin]

    def _get_user_uuid(self) -> uuid.UUID:
        raw = self.kwargs.get('instructor_pk')
        try:
            return uuid.UUID(str(raw))
        except (TypeError, ValueError):
            raise ValidationError({'instructor_pk': 'Value must be a valid UUID string.'})

    def _get_instructor(self):
        user_uuid = self._get_user_uuid()
        return get_object_or_404(Instructor, user_id=user_uuid)

    def get_queryset(self):
        # Filter by the instructor’s user UUID (not the Instructor.pk)
        return Certification.objects.filter(instructor__user_id=self._get_user_uuid())

    def list(self, request, *args, **kwargs):
        # Using pagination
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def perform_create(self, serializer):
        # Resolve the Instructor via the user UUID, then save
        serializer.save(instructor=self._get_instructor())


class InstructorProfileViewSet(RetrieveProfileMixin, UpdateProfileMixin, viewsets.GenericViewSet):
    """
    View for handling instructor profile operations.
    This view allows instructors to retrieve and update their profile information.
    """
    tag_name = "Instructor Profile"
    serializer_class = InstructorProfileSerializer  # Assuming the same serializer is used for instructors
    permission_classes = [app_permissions.IsInstructor]

    def get_object(self):
        """
        Retrieve the user profile of the currently authenticated instructor.
        :return:
        """
        user_id = self.request.user.id
        try:
            return self.serializer_class.Meta.model.objects.get(user_id=user_id)
        except self.serializer_class.Meta.model.DoesNotExist:
            raise ValidationError({'detail': 'User profile not found.'})

    def get_queryset(self):
        """
        Return the queryset for the user profile.
        This queryset is filtered to return only the authenticated user's profile.
        :return:
        """
        return self.serializer_class.Meta.model.objects.filter(user_id=self.request.user.id)


class AdminProfileViewSet(RetrieveProfileMixin, UpdateProfileMixin, viewsets.GenericViewSet):
    """
    View for handling admin profile operations.
    This view allows admins to retrieve and update their profile information.
    """
    tag_name = 'Admin Profile'
    serializer_class = AdminProfileSerializer
    permission_classes = [app_permissions.IsAdmin]

    def get_object(self):
        """
        Retrieve the user profile of the currently authenticated admin.
        :return:
        """
        user_id = self.request.user.id
        try:
            return self.serializer_class.Meta.model.objects.get(user_id=user_id)
        except self.serializer_class.Meta.model.DoesNotExist:
            raise ValidationError({'detail': 'User profile not found.'})

    def get_queryset(self):
        """
        Return the queryset for the user profile.
        This queryset is filtered to return only the authenticated user's profile.
        :return:
        """
        return self.serializer_class.Meta.model.objects.filter(user_id=self.request.user.id)


class UserAccountDeleteViewSet(viewsets.GenericViewSet):
    """
    View for deleting admin profile information (DELETE).
    """
    tag_name = 'Authentication'
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        user_id = self.request.user.id
        try:
            return self.serializer_class.Meta.model.objects.get(id=user_id)
        except self.serializer_class.Meta.model.DoesNotExist:
            raise ValidationError({'detail': 'User not found.'})

    def get_queryset(self):
        return self.serializer_class.Meta.model.objects.filter(id=self.request.user.id)

    # @swagger_auto_schema(
    #     operation_summary='Delete Account',
    #     operation_description='Allows current user to delete their account.',
    #     responses={
    #         200: openapi.Response(
    #             'Success',
    #             openapi.Schema(type=openapi.TYPE_STRING, description='Account deleted successfully')
    #         ),
    #         400: openapi.Response('Bad request'),
    #         401: openapi.Response(
    #             'Unauthorized',
    #             openapi.Schema(type=openapi.TYPE_STRING, description='User not authenticated')
    #         ),
    #     }
    # )
    @action(methods=['delete'], detail=False, url_path='delete-account')
    def delete_account(self, request, *args, **kwargs):
        """
        Handle the deletion of the admin profile.
        :param request:
        :return:
        """
        user = request.user
        user.delete()
        return Response({
            'message': 'Account deleted successfully'
        }, status=status.HTTP_204_NO_CONTENT)


class RegisterViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """
    View for handling user registration.
    This view allows new users to register by creating a new user profile.
    """
    tag_name = 'Authentication'
    serializer_class = RegistrationSerializer
    permission_classes = []  # No authentication required for registration

    # @swagger_auto_schema(
    #     responses={
    #         201: openapi.Response('Success', RegistrationLoginResponseSerializer),
    #         400: openapi.Response('Bad request'),
    #     }
    # )
    def create(self, request, *args, **kwargs):
        """
        Handle the creation of a new user profile.
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.save()

            # Generate tokens or perform any additional registration logic here -
            # For example, you can return a token or user data
            return Response({
                'message': 'Registration successful, Check your email for OTP verification',
                'user': RegistrationSerializer(user).data
                # 'jwt_token': get_tokens_for_user(user)  # Assuming get_tokens_for_user is defined in a User model
            }, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response({
                'message': 'Registration failed',
                'errors': e.detail
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'message': 'Server Failure',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """
    View for handling user login.
    This view allows users to log in by providing their credentials.
    """
    tag_name = 'Authentication'
    serializer_class = LoginSerializer
    permission_classes = []  # No authentication required for login

    def perform_create(self, serializer):
        """
        Override the perform_create method to handle user login.
        This method authenticates the user based on provided credentials.
        """
        serializer.save()

    # @swagger_auto_schema(
    #     responses={
    #         200: openapi.Response('Success', RegistrationLoginResponseSerializer),
    #         400: openapi.Response('Bad request'),
    #     }
    # )
    def create(self, request, *args, **kwargs):
        """
        Handle the creation of a user login session.
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        # Generate tokens or perform any additional login logic here -
        # For example, you can return a token or user data
        return Response({
            'message': 'Login successful',
            'user': UserSerializer(user).data,
            'jwt_token': get_tokens_for_user(user)  # Assuming get_tokens_for_user is defined in a User model
        }, status=status.HTTP_200_OK)


class LogoutViewSet(viewsets.GenericViewSet):
    """
    View for handling user logout.
    This view allows users to log out by invalidating their session or tokens.
    """
    tag_name = 'Authentication'
    serializer_class = LogoutSerializer
    permission_classes = [permissions.IsAuthenticated]

    # @swagger_auto_schema(
    #     operation_summary='Logout User',
    #     operation_description='Logs out the user by invalidating their session or tokens.',
    #     methods=['post'],
    #     responses={
    #         200: openapi.Response('Success', openapi.Schema(type=openapi.TYPE_STRING, description='Logout successful')),
    #         401: openapi.Response('Unauthorized', openapi.Schema(type=openapi.TYPE_STRING, description='User not authenticated')),
    #     }
    # )
    @action(detail=False, methods=['post'], url_path='logout')
    def logout(self, request):
        """
        Handle user logout.
        """
        if not request.user.is_authenticated:
            return Response({'message': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

        # Invalidate the session or token if applicable
        if hasattr(request, 'auth') and request.auth:
            try:
                request.auth.delete()
            except AttributeError:
                pass  # If auth object does not support delete

        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "Successfully logged out."}, status=status.HTTP_204_NO_CONTENT)


class VerifyOTPViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """
    View for handling OTP verification.
    This view allows users to verify their OTPs for registration or other purposes.
    """
    tag_name = 'Authentication'
    serializer_class = VerifyOTPSerializer
    permission_classes = []  # No authentication required for OTP verification

    # @swagger_auto_schema(
    #     operation_summary='Verify OTP',
    #     operation_description='Allows users to verify their OTPs for registration or other purposes.',
    #     request_body=VerifyOTPSerializer,
    #     responses={
    #         200: openapi.Response('Success', openapi.Schema(type=openapi.TYPE_STRING, description='OTP verified successfully')),
    #         400: openapi.Response('Bad request'),
    #     }
    # )
    def create(self, request, *args, **kwargs):
        """
        Handle the creation of an OTP verification request.
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "OTP verified successfully."}, status=status.HTTP_200_OK)


class ForgotPasswordViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """
    View for handling forgot password requests.
    This view allows users to request a password reset by providing their email.
    """
    tag_name = 'Authentication'
    serializer_class = ForgotPasswordSerializer
    permission_classes = []  # No authentication required for forgot password

    # @swagger_auto_schema(
    #     operation_summary='Forgot Password',
    #     operation_description='Allows users to request a password reset by providing their email.',
    #     responses={
    #         200: openapi.Response('Success', openapi.Schema(type=openapi.TYPE_STRING, description='Password reset email sent')),
    #         400: openapi.Response('Bad request'),
    #     }
    # )
    def create(self, request, *args, **kwargs):
        """
        Handle the creation of a forgot password request.
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "Password reset email sent."}, status=status.HTTP_200_OK)


class ResetPasswordViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """
    View for handling password reset requests.
    This view allows users to reset their password using a valid OTP.
    """
    tag_name = 'Authentication'
    serializer_class = ResetPasswordSerializer
    permission_classes = []  # No authentication required for reset password

    # @swagger_auto_schema(
    #     operation_summary='Reset Password',
    #     operation_description='After using Forgot Password, this allows users to reset their password using a valid OTP.',
    #     request_body=ResetPasswordSerializer,
    #     responses={
    #         200: openapi.Response('Success', openapi.Schema(type=openapi.TYPE_STRING, description='Password reset successful')),
    #         400: openapi.Response('Bad request'),
    #     }
    # )
    def create(self, request, *args, **kwargs):
        """
        Handle the creation of a password reset request.
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "Password reset successful."}, status=status.HTTP_200_OK)


class ChangePasswordViewSet(viewsets.GenericViewSet):
    """
    View for handling password change requests.
    This view allows authenticated users to change their password.
    """
    tag_name = 'Authentication'
    serializer_class = ChangePasswordSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """
        Return the queryset for the user profile.
        This queryset is filtered to return only the authenticated user's profile.
        :return:
        """
        user = get_user_model()
        return user.objects.filter(id=self.request.user.id)

    # @swagger_auto_schema(
    #     operation_summary='Change Password',
    #     operation_description='Allows authenticated users to change their password.',
    #     responses={
    #         200: openapi.Response(
    #             'Success',
    #             openapi.Schema(type=openapi.TYPE_STRING, description='Password changed successfully')
    #         ),
    #         400: openapi.Response('Bad request'),
    #         401: openapi.Response(
    #             'Unauthorized',
    #             openapi.Schema(type=openapi.TYPE_STRING, description='User not authenticated')
    #         ),
    #     }
    # )
    @action(detail=False, methods=['post'], url_path='change-password')
    def change_password(self, request):
        """
        Handle the change password request.
        :param request:
        :return:
        """
        if not request.user.is_authenticated:
            return Response({'message': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "Password changed successfully."}, status=status.HTTP_200_OK)