from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

from . import views

router = DefaultRouter()
# for admins
router.register(r'admin/profile', views.AdminProfileRetrieveViewSet, basename='admin-profile')
router.register(r'admin/profile', views.AdminProfileUpdateViewSet, basename='admin-update-profile')

# router.register(r'instructor/profile', views.InstructorProfileViewSet, basename='instructor-profile')
# router.register(r'sponsor/profile', views.SponsorProfileViewSet, basename='sponsor-profile')
# router.register(r'student/profile', views.StudentProfileViewSet, basename='student-profile')
router.register(r'register', views.RegisterViewSet, basename='register')
router.register(r'login', views.LoginViewSet, basename='login')
router.register(r'logout', views.LogoutViewSet, basename='logout')
router.register(r'otp/verify', views.VerifyOTPViewSet, basename='verify-otp')
router.register(r'user/forgot-password', views.ForgotPasswordViewSet, basename='forgot-password')
router.register(r'user/reset-password', views.ResetPasswordViewSet, basename='reset-password')
router.register(r'user/change-password', views.ChangePasswordViewSet, basename='change-password')
router.register(r'user/delete-account', views.UserAccountDeleteViewSet, basename='delete-user-account')

urlpatterns = [
    path('', include(router.urls)),
    # path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
]
