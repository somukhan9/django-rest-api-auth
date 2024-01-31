from rest_framework import views
from rest_framework import generics
from rest_framework import mixins
from rest_framework import permissions
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model, authenticate

from .serializers import (
    UserSerializer,
    LoginUserSerializer,
    ChangePasswordSerializer,
    SendPasswordResetEmailSerializer,
    ResetPasswordSerializer
)
from .renderers import AuthAppRenderer

User = get_user_model()


def get_auth_token(user):
    refresh = RefreshToken.for_user(user=user)

    return {
        "access": str(refresh.access_token),
        "refresh": str(refresh)
    }


class CreateUserView(
    mixins.CreateModelMixin,
    generics.GenericAPIView,
):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]
    renderer_classes = [AuthAppRenderer]

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class LoginUserAPIView(views.APIView):
    permission_classes = [permissions.AllowAny]
    renderer_classes = [AuthAppRenderer]

    def post(self, request, format=None):
        serializer = LoginUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username_or_email = serializer.data.get("username_or_email")
        password = serializer.data.get("password")

        user = authenticate(
            request, username=username_or_email, password=password)

        if user is not None:
            token = get_auth_token(user=user)
            return Response({"detail": "User Logged In Successfully!", "token": token}, status=status.HTTP_200_OK)

        return Response({"errors": {"non_field_errors": ["Invalid Credentials!"]}}, status=status.HTTP_400_BAD_REQUEST)


class ProfileAPIView(views.APIView):
    renderer_classes = [AuthAppRenderer]

    def get(self, request, format=None):
        serializer = UserSerializer(request.user)

        return Response({"detail": "Profile data fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)


class ChangePasswordAPIView(views.APIView):
    renderer_classes = [AuthAppRenderer]

    def post(self, request, format=None):
        serializer = ChangePasswordSerializer(
            data=request.data, context={"user": request.user})

        serializer.is_valid(raise_exception=True)

        return Response({"detail": "Password changed successfully!"},
                        status=status.HTTP_200_OK)


class SendResetPasswordEmailAPIView(views.APIView):
    renderer_classes = [AuthAppRenderer]
    permission_classes = [permissions.AllowAny]

    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(
            {"detail": "Check Your Email. Password Reset link has been sent to your email."})


class ResetPasswordAPIView(views.APIView):
    renderer_classes = [AuthAppRenderer]
    permission_classes = [permissions.AllowAny]

    def post(self, request, uid, token, format=None):
        serializer = ResetPasswordSerializer(data=request.data, context={
                                             "uid": uid, "token": token})
        serializer.is_valid(raise_exception=True)
        return Response({"detail": "Password reset successfully!"})
