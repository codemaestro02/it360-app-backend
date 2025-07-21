from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

from . import views

router = DefaultRouter()

router.register(r'user/student/profile', views.StudentProfileViewSet, basename='user-profile')
router.register(r'register', views.RegisterViewSet, basename='register')
router.register(r'login', views.LoginViewSet, basename='login')
router.register(r'', views.LogoutViewSet, basename='logout')
router.register(r'otp/verify', views.VerifyOTPViewSet, basename='verify-otp')
router.register(r'user/forgot-password', views.ForgotPasswordViewSet, basename='forgot-password')
router.register(r'user/reset-password', views.ResetPasswordViewSet, basename='reset-password')
router.register(r'user', views.ChangePasswordViewSet, basename='change-password')

urlpatterns = [
    path('', include(router.urls)),
    # path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
]
