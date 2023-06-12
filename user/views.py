import random

from django.contrib.auth.hashers import make_password, check_password
from django.core.mail import send_mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from user.models import User, UserProfile
from user.serializers import UserProfileSerializer

from .serializers import UserSerializer


def send_otp_email(email, otp):
    # Generate OTP (e.g., random 6-digit number)
    # Save the OTP for later verification (e.g., store in the database)
    # Send OTP via email
    send_mail(
        'OTP Verification',
        f'Your OTP is: {otp}',
        'shahiljoshi9827@gmail.com',
        [email],
        fail_silently=False,
    )


def generate_otp():
    return str(random.randint(100000, 999999))


class UserViewSet(GenericViewSet):
    queryset = User.objects.all()

    @action(methods=['POST'], detail=False)
    def register(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'], detail=False)
    def login(self, request):
        email = request.data.get('email')

        # Validate email
        if not email:
            return Response({'error': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)
        # Retrieve the user associated with the email
        user = User.objects.filter(email=email).first()

        if not user:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Generate OTP
        otp = generate_otp()
        user.otp = otp
        user.save()

        # Send OTP via email
        send_otp_email(email, otp)

        return Response({'success': 'OTP sent to your email.'}, status=status.HTTP_200_OK)

    @action(methods=['PUT'], detail=False)
    def otp_verification(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        otp = request.data.get('otp')

        # Validate email and OTP
        if not email or not otp:
            return Response({'error': 'Email and OTP are required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Retrieve the user associated with the email

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Verify the OTP
        if not check_password(password, user.password):
            raise NotFound

        if otp != user.otp:
            return Response({'error': 'Invalid OTP.'}, status=status.HTTP_401_UNAUTHORIZED)

        # Generate JWT token or perform any other desired actions

        refresh = RefreshToken.for_user(user)

        return Response({'success': 'Logged in successfully.', 'token': str(refresh.access_token)},
                        status=status.HTTP_200_OK)

    @action(methods=['POST'], detail=False, permission_classes=[IsAuthenticated],
            authentication_classes=[JWTAuthentication])
    def change_password(self, request):
        user = request.user
        password = request.data.get('password')
        user.password = make_password(password)
        user.save()
        return Response({"message": "Password Changed Successfully"}, status=status.HTTP_200_OK)

    @action(methods=['POST'], detail=False)
    def forget_password(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            reset_link = f"http://127.0.0.1:8000/reset_password/?uid={uid}"
            # Send the reset_link via email to the user
            send_mail('Password Reset', f'Click the link to reset your password: {reset_link}',
                      'shahiljoshi9827@gmail.com',
                      [email])
        except User.DoesNotExist:
            pass
        return Response({"message": "Password Reset Link Sent Via Email"}, status=status.HTTP_200_OK)

    @action(methods=['POST'], detail=False)
    def reset_password(self, request):
        try:
            uidb64 = request.query_params.get('uid')
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)

            if user:
                # Retrieve the new password from the request
                new_password = request.data.get('new_password')

                # Set the new password for the user
                user.set_password(new_password)
                user.save()

                # Send a confirmation email to the user
                send_mail(
                    'Password Reset Confirmation',
                    'Your password has been successfully reset.',
                    'shahiljoshi9827@gmail.com',
                    [user.email],
                    fail_silently=False,
                )

                # Password reset successful
                return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
            else:
                # Token is invalid or expired
                return Response({'message': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            # Invalid user ID or user does not exist
            return Response({'message': 'Invalid user ID'}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['PUT'], detail=False, permission_classes=[IsAuthenticated],
            authentication_classes=[JWTAuthentication])
    def update_profile(self, request):
        user = self.get_object()
        user_profile, created = UserProfile.objects.get_or_create(user=user)
        serializer = UserProfileSerializer(data=request.data, instance=user_profile)
        if not serializer.is_valid(raise_exception=True):
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
