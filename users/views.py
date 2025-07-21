from django.contrib.auth import get_user_model
from rest_framework import viewsets, mixins, status, permissions
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .serializers import (
    RegistrationSerializer, VerifyOTPSerializer, LoginSerializer,
    LogoutSerializer, ForgotPasswordSerializer, ResetPasswordSerializer,
    ChangePasswordSerializer, StudentProfileSerializer, RegistrationLoginResponseSerializer, UserSerializer
)
from .utils import get_tokens_for_user


class StudentProfileViewSet(mixins.RetrieveModelMixin, mixins.UpdateModelMixin, viewsets.GenericViewSet):
    """
    View for handling user profile operations.
    This view allows users to retrieve and update their profile information.
    """
    serializer_class = StudentProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

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

    def update(self, request, *args, **kwargs):
        """
        Handle the update of the user profile.
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        return Response({
            'message': 'Profile updated successfully',
            'user': serializer.data
        }, status=status.HTTP_200_OK)


class RegisterViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """
    View for handling user registration.
    This view allows new users to register by creating a new user profile.
    """
    serializer_class = RegistrationSerializer
    permission_classes = []  # No authentication required for registration

    @swagger_auto_schema(
        responses={
            201: openapi.Response('Success', RegistrationLoginResponseSerializer),
            400: openapi.Response('Bad request'),
        }
    )
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
                'user': RegistrationSerializer(user).data,
                'jwt_token': get_tokens_for_user(user)  # Assuming get_tokens_for_user is defined in a User model
            }, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response({
                'message': 'Registration failed',
                'errors': e.detail
            }, status=status.HTTP_400_BAD_REQUEST)


class LoginViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """
    View for handling user login.
    This view allows users to log in by providing their credentials.
    """
    serializer_class = LoginSerializer
    permission_classes = []  # No authentication required for login

    def perform_create(self, serializer):
        """
        Override the perform_create method to handle user login.
        This method authenticates the user based on provided credentials.
        """
        serializer.save()

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Success', RegistrationLoginResponseSerializer),
            400: openapi.Response('Bad request'),
        }
    )
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
    serializer_class = LogoutSerializer
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_summary='Logout User',
        operation_description='Logs out the user by invalidating their session or tokens.',
        methods=['post'],
        responses={
            200: openapi.Response('Success', openapi.Schema(type=openapi.TYPE_STRING, description='Logout successful')),
            401: openapi.Response('Unauthorized', openapi.Schema(type=openapi.TYPE_STRING, description='User not authenticated')),
        }
    )
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
    serializer_class = VerifyOTPSerializer
    permission_classes = []  # No authentication required for OTP verification

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Success', openapi.Schema(type=openapi.TYPE_STRING, description='OTP verified successfully')),
            400: openapi.Response('Bad request'),
        }
    )
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
    serializer_class = ForgotPasswordSerializer
    permission_classes = []  # No authentication required for forgot password

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Success', openapi.Schema(type=openapi.TYPE_STRING, description='Password reset email sent')),
            400: openapi.Response('Bad request'),
        }
    )
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
    serializer_class = ResetPasswordSerializer
    permission_classes = []  # No authentication required for reset password

    @swagger_auto_schema(
        responses={
            200: openapi.Response('Success', openapi.Schema(type=openapi.TYPE_STRING, description='Password reset successful')),
            400: openapi.Response('Bad request'),
        }
    )
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

    @swagger_auto_schema(
        operation_summary='Change Password',
        operation_description='Allows authenticated users to change their password.',
        responses={
            200: openapi.Response(
                'Success',
                openapi.Schema(type=openapi.TYPE_STRING, description='Password changed successfully')
            ),
            400: openapi.Response('Bad request'),
            401: openapi.Response(
                'Unauthorized',
                openapi.Schema(type=openapi.TYPE_STRING, description='User not authenticated')
            ),
        }
    )
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
        serializer.save(user=request.user)
        return Response({"detail": "Password changed successfully."}, status=status.HTTP_200_OK)