from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import User
from .serializers import UserSerializer, UserRegistrationSerializer, UserProfileUpdateSerializer, OTPVerificationSerializer
from django.core.mail import send_mail
import random
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.throttling import SimpleRateThrottle
from .throttles import SignupRateThrottle, LoginRateThrottle, OTPVerificationRateThrottle
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken, TokenError, AccessToken
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.utils import timezone
from datetime import timedelta
from .token_utils import get_tokens_for_user
import traceback
from django.contrib.auth import get_user_model
User = get_user_model()
from django.core.cache import cache
from datetime import datetime
from django.contrib.auth.models import AnonymousUser
import jwt
from django.conf import settings
from datetime import datetime
from hashlib import sha256
from .models import User
from datetime import datetime, timedelta




class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.data.get('refresh')
        try:
            token = RefreshToken(refresh_token)
            user = token.user
            if user.last_activity and timezone.now() - user.last_activity > timedelta(hours=1):
                return Response({"detail": "Token has expired due to inactivity."}, status=status.HTTP_401_UNAUTHORIZED)
            return Response(get_tokens_for_user(user))
        except InvalidToken:
            return Response({"detail": "Invalid token."}, status=status.HTTP_401_UNAUTHORIZED)

class UserRegistrationView(APIView):
    throttle_classes = [SignupRateThrottle]
    
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            otp = str(random.randint(100000, 999999))
            user.set_email_verification_code(otp)
            send_mail(
                'Email Verification',
                f'Your verification code is: {otp}. This code will expire in 10 minutes.',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            user_data = UserSerializer(user).data
            return Response({'message': 'User registered successfully', 'user': user_data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    throttle_classes = [LoginRateThrottle]
    
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        try:
            user = User.objects.get(email=email)
            if user.check_password(password):
                if user.is_active:
                    refresh = RefreshToken.for_user(user)
                    user_data = UserSerializer(user).data
                    response_data = {
                        "message": "Login successful",
                        "user": user_data,
                        "refresh": str(refresh),
                        "access": str(refresh.access_token)
                    }
                    return Response(response_data, status=status.HTTP_200_OK)
                else:
                    return Response({'error': 'Account not verified'}, status=status.HTTP_403_FORBIDDEN)
            else:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
class UserProfileView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserProfileUpdateView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def put(self, request):
        user = request.user
        serializer = UserProfileUpdateSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            user_data = UserSerializer(user).data
            response_data = {
                "message": "Profile updated successfully",
                "user": {
                    "account_id": user.account_id,  # Assuming you have an account_id field
                    "first_name": user.first_name,
                    "last_name": user.last_name
                }
            }
            return Response(response_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class OTPVerificationRateThrottle(SimpleRateThrottle):
    scope = 'otp_verification'

    def get_cache_key(self, request, view):
        email = request.data.get('email')
        if email:
            ident = email
        else:
            ident = self.get_ident(request)
        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }
    
class OTPVerificationView(APIView):
    throttle_classes = [OTPVerificationRateThrottle]
    
    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']

            try:
                user = User.objects.get(email=email)
                if user.is_active:
                    return Response({'message': 'Account is already verified'}, status=status.HTTP_200_OK)
                if user.email_verification_code == otp:
                    if user.is_email_verification_code_valid():
                        user.is_active = True
                        user.email_verification_code = None
                        user.email_verification_code_created_at = None
                        user.save()
                        refresh = RefreshToken.for_user(user)
                        return Response({
                            'message': 'Account verified successfully',
                            'refresh': str(refresh),
                            'access': str(refresh.access_token)
                        }, status=status.HTTP_200_OK)
                    else:
                        return Response({'error': 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResendOTPView(APIView):
    throttle_classes = [OTPVerificationRateThrottle]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            if user.is_active:
                return Response({'message': 'Account is already verified'}, status=status.HTTP_200_OK)

            # Generate new OTP
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
            user.set_email_verification_code(otp)

            # Send email with new OTP
            subject = 'Your New OTP for Account Verification'
            message = f'Your new OTP is: {otp}. It will expire in 10 minutes.'
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )

            return Response({'message': 'New OTP sent successfully'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        

class PasswordResetView(APIView):
    throttle_classes = [OTPVerificationRateThrottle]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            
            # Generate OTP for password reset
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
            user.set_email_verification_code(otp)

            # Send email with OTP for password reset
            subject = 'Password Reset OTP'
            message = f'Your OTP for password reset is: {otp}. It will expire in 10 minutes.'
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )

            return Response({'message': 'Password reset OTP sent successfully'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')
        new_password = request.data.get('new_password')

        if not all([email, otp, new_password]):
            return Response({'error': 'Email, OTP, and new password are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            
            if user.email_verification_code == otp and user.is_email_verification_code_valid():
                user.set_password(new_password)
                user.email_verification_code = None
                user.email_verification_code_created_at = None
                user.save()
                return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)





class UserLogoutView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Get the access token from the request
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return Response({'error': 'No valid token found in Authorization header'}, status=status.HTTP_401_UNAUTHORIZED)
            
            access_token = auth_header.split(' ')[1]
            
            # Get the user from the access token
            payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=['HS256'])
            user = request.user
            
            # Generate a cache key using a hash of the access token
            cache_key = f'blacklist_access_token_{sha256(access_token.encode()).hexdigest()}'
            
            # Add the access token to the blacklist
            exp_date = datetime.fromtimestamp(payload['exp'])
            cache.set(cache_key, True, timeout=(exp_date - datetime.now()).total_seconds())
            
            # Update user's last activity
            user.last_activity = None
            user.save()
            
            # Set the user to anonymous to prevent further access
            request.user = AnonymousUser()
            
            return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'error': f'An unexpected error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)






