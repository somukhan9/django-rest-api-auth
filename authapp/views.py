from rest_framework import views
from rest_framework import generics
from rest_framework import mixins
from rest_framework import permissions
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenViewBase

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
            response = Response(
                {"detail": "User Logged In Successfully!", "data": token, "statusCode": status.HTTP_200_OK, "success": True}, status=status.HTTP_200_OK)

            """
            TODO: set the secure option to True for production
            """

            response.set_cookie(
                "access_token", token["access"], httponly=True, secure=False)
            response.set_cookie(
                "refresh_token", token["refresh"], httponly=True, secure=False)
            return response

        return Response({"errors": {"non_field_errors": ["Invalid Credentials!"]}, "statusCode": status.HTTP_400_BAD_REQUEST, "success": False}, status=status.HTTP_400_BAD_REQUEST)


class Logout(views.APIView):
    renderer_classes = [AuthAppRenderer]

    def get(self, request, *args, **kwargs):
        response = Response(
            {"detail": "Logged out successfully", "data": None, "statusCode": status.HTTP_200_OK, "success": True}, status=status.HTTP_200_OK)

        """
        TODO: set the secure option to True for production
        """
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")

        return response


class CustomTokenRefreshView(TokenViewBase):
    renderer_classes = [AuthAppRenderer]

    """
    Custom view for refreshing tokens.
    """

    def post(self, request, *args, **kwargs):
        refresh_token = request.data.get("refresh", "")

        if not refresh_token and "refresh_token" in request.COOKIES:
            refresh_token = request.COOKIES["refresh_token"]

        if not refresh_token:
            return Response({"detail": "Refresh Token not provided"}, status=status.HTTP_400_BAD_REQUEST)

        try:

            # Create a new access token and refresh token
            new_access_token = RefreshToken(refresh_token).access_token

            """
            If we want to generate a new refresh token while refreshing the access token
            so that the regular user can logged in for a long time
            """
            # new_refresh_token = RefreshToken(
            #     refresh_token).for_user(request.user)

            response_data = {
                'access': str(new_access_token),
                # 'refresh': str(new_refresh_token),
            }

            response = Response({"detail": "Access token refreshed successfully",
                                "data": response_data, "statusCode": status.HTTP_200_OK, "success": True}, status=status.HTTP_200_OK)

            """
            TODO: set the secure option to True for production
            """

            response.set_cookie(
                "access_token", new_access_token, httponly=True, secure=False)
            # response.set_cookie("refresh_token", new_refresh_token, httponly=True, secure=False)

            return response

        except Exception as e:
            return Response({"errors": {"non_field_errors": [f"Error refreshing tokens: {str(e)}"]}, "statusCode": status.HTTP_403_FORBIDDEN, "success": False}, status=status.HTTP_403_FORBIDDEN)


class ProfileAPIView(views.APIView):
    renderer_classes = [AuthAppRenderer]

    def get(self, request, format=None):
        serializer = UserSerializer(request.user)

        return Response({"detail": "Profile data fetched successfully", "data": serializer.data, "statusCode": status.HTTP_200_OK, "success": True}, status=status.HTTP_200_OK)


class ChangePasswordAPIView(views.APIView):
    renderer_classes = [AuthAppRenderer]

    def post(self, request, format=None):
        serializer = ChangePasswordSerializer(
            data=request.data, context={"user": request.user})

        serializer.is_valid(raise_exception=True)

        return Response({"detail": "Password changed successfully!", "data": None, "statusCode": status.HTTP_200_OK, "success": True},
                        status=status.HTTP_200_OK)


class SendResetPasswordEmailAPIView(views.APIView):
    renderer_classes = [AuthAppRenderer]
    permission_classes = [permissions.AllowAny]

    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(
            {"detail": "Check Your Email. Password Reset link has been sent to your email.", "data": None, "statusCode": status.HTTP_200_OK, "success": True}, status=status.HTTP_200_OK)


class ResetPasswordAPIView(views.APIView):
    renderer_classes = [AuthAppRenderer]
    permission_classes = [permissions.AllowAny]

    def post(self, request, uid, token, format=None):
        serializer = ResetPasswordSerializer(data=request.data, context={
                                             "uid": uid, "token": token})
        serializer.is_valid(raise_exception=True)
        return Response({"detail": "Password reset successfully!", "data": None, "statusCode": status.HTTP_200_OK, "success": True}, status=status.HTTP_200_OK)
