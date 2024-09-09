from django.urls import path
from .views import UserRegistrationView, UserLoginView, UserProfileUpdateView, PasswordResetView, OTPVerificationView, ResendOTPView, CustomTokenRefreshView, UserLogoutView, UserProfileView

urlpatterns = [
    path('signup/', UserRegistrationView.as_view(), name='signup'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('otp-verification/', OTPVerificationView.as_view(), name='otp-verification'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('profile-update/', UserProfileUpdateView.as_view(), name='profile-update'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    path('password-reset/', PasswordResetView.as_view(), name='password-reset'),
    path('profile-update/', UserProfileUpdateView.as_view(), name='profile-update'),
    path('api/token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', UserLogoutView.as_view(), name='logout'),
]