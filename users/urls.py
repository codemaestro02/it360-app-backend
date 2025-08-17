from django.urls import path, include
from rest_framework_nested import routers
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

from . import views
from core.routers import CoreRouter

router = CoreRouter()

# for admins
router.register(r'admin/profile', views.AdminProfileViewSet, basename='admin-profile')
router.register(r'instructor/profile', views.InstructorProfileViewSet, basename='instructor-profile')
cert_router = routers.NestedSimpleRouter(router, r'instructor/profile', lookup='instructor')
cert_router.register(r'certifications', views.CertificationViewSet, basename='instructor-profile-certifications')

router.register(r'sponsor/profile', views.SponsorProfileViewSet, basename='sponsor-profile')
router.register(r'sponsor', views.SponsorLinkStudentViewSet, basename='sponsor-link-student')

router.register(r'student/profile', views.StudentProfileViewSet, basename='student-profile')
router.register(r'register', views.RegisterViewSet, basename='register')
router.register(r'login', views.LoginViewSet, basename='login')
router.register(r'', views.LogoutViewSet, basename='logout')
router.register(r'otp/verify', views.VerifyOTPViewSet, basename='verify-otp')
router.register(r'user/forgot-password', views.ForgotPasswordViewSet, basename='forgot-password')
router.register(r'user/reset-password', views.ResetPasswordViewSet, basename='reset-password')
router.register(r'user', views.ChangePasswordViewSet, basename='change-password')
router.register(r'user', views.UserAccountDeleteViewSet, basename='delete-account')

urlpatterns = [
    path('', include(router.urls + cert_router.urls)),
    # JWT Token URLs
    # path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
]
