from rest_framework import views
from rest_framework import generics
from rest_framework import mixins
from rest_framework import permissions
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import (
    TokenViewBase,
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)

from django.utils.datastructures import MultiValueDict

from django.conf import settings


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
        response = self.create(request, *args, **kwargs)

        # Extract relevant information from the response object
        serializer_data = response.data

        # Customize the response
        response_data = {
            "detail": "Registration Successful!",
            "statusCode": response.status_code,
            "success": True,
            "data": serializer_data,  # Assign serializer data
        }

        return Response(response_data, status=response.status_code)


class LoginUserAPIView(TokenObtainPairView):
    renderer_classes = [AuthAppRenderer]
    permission_classes = [permissions.AllowAny]

    def post(self, request: views.Request, *args, **kwargs) -> Response:
        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:

            access_token = response.data.pop("access")
            refresh_token = response.data.pop("refresh")

            response.set_cookie(
                settings.AUTH_COOKIE_ACCESS_TOKEN_KEY, access_token, httponly=settings.AUTH_COOKIE_HTTP_ONLY, secure=settings.AUTH_COOKIE_SECURE, max_age=settings.AUTH_COOKIE_ACCESS_TOKEN_MAX_AGE, path=settings.AUTH_COOKIE_PATH, samesite=settings.AUTH_COOKIE_SAME_SITE
            )

            response.set_cookie(
                settings.AUTH_COOKIE_REFRESH_TOKEN_KEY, refresh_token, httponly=settings.AUTH_COOKIE_HTTP_ONLY, secure=settings.AUTH_COOKIE_SECURE, max_age=settings.AUTH_COOKIE_REFRESH_TOKEN_MAX_AGE, path=settings.AUTH_COOKIE_PATH, samesite=settings.AUTH_COOKIE_SAME_SITE
            )

            response.data["detail"] = "User Logged In Successfully!"
            response.data["statusCode"] = response.status_code
            response.data["success"] = True
            response.data["data"] = {
                settings.AUTH_COOKIE_ACCESS_TOKEN_KEY: access_token, settings.AUTH_COOKIE_REFRESH_TOKEN_KEY: refresh_token
            }

        return response


class Logout(views.APIView):
    renderer_classes = [AuthAppRenderer]

    def get(self, request, *args, **kwargs):
        response = Response(
            {"detail": "Logged out successfully", "data": None, "statusCode": status.HTTP_200_OK, "success": True}, status=status.HTTP_200_OK)

        """
        TODO: set the secure option to True for production
        """

        response.set_cookie(
            settings.AUTH_COOKIE_ACCESS_TOKEN_KEY, None, httponly=settings.AUTH_COOKIE_HTTP_ONLY, secure=settings.AUTH_COOKIE_SECURE, max_age=settings.AUTH_COOKIE_ACCESS_TOKEN_MAX_AGE, path=settings.AUTH_COOKIE_PATH, samesite=settings.AUTH_COOKIE_SAME_SITE
        )

        response.set_cookie(
            settings.AUTH_COOKIE_REFRESH_TOKEN_KEY, None, httponly=settings.AUTH_COOKIE_HTTP_ONLY, secure=settings.AUTH_COOKIE_SECURE, max_age=settings.AUTH_COOKIE_REFRESH_TOKEN_MAX_AGE, path=settings.AUTH_COOKIE_PATH, samesite=settings.AUTH_COOKIE_SAME_SITE
        )

        return response


"""
Custom view for refreshing tokens.
"""


class CustomTokenRefreshView(TokenRefreshView):
    renderer_classes = [AuthAppRenderer]

    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get(
            settings.AUTH_COOKIE_REFRESH_TOKEN_KEY)

        if refresh_token:
            request.data["refresh"] = refresh_token

        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            access_token = response.data.pop(
                settings.AUTH_COOKIE_ACCESS_TOKEN_KEY)
            # refresh_token = response.data.pop(settings.COOKIE_REFRESH_TOKEN_KEY)

            response.set_cookie(
                settings.AUTH_COOKIE_ACCESS_TOKEN_KEY, access_token, httponly=settings.AUTH_COOKIE_HTTP_ONLY, secure=settings.AUTH_COOKIE_SECURE, max_age=settings.AUTH_COOKIE_ACCESS_TOKEN_MAX_AGE, path=settings.AUTH_COOKIE_PATH, samesite=settings.AUTH_COOKIE_SAME_SITE
            )
            # response.set_cookie(
            #     settings.COOKIE_REFRESH_TOKEN_KEY, refresh_token, httponly=True, secure=False)

            response.data["detail"] = "Access Token Refreshed Successfully!"
            response.data["statusCode"] = response.status_code
            response.data["success"] = True
            response.data["data"] = {
                settings.AUTH_COOKIE_ACCESS_TOKEN_KEY: access_token,
                # settings.COOKIE_REFRESH_TOKEN_KEY: refresh_token
            }

        return response


class CustomTokenVerifyView(TokenVerifyView):
    def post(self, request: views.Request, *args, **kwargs) -> Response:
        access_token = request.COOKIES.get(
            settings.AUTH_COOKIE_ACCESS_TOKEN_KEY)

        refresh_token = request.COOKIES.get(
            settings.AUTH_COOKIE_REFRESH_TOKEN_KEY)

        print("Access token: %s" % access_token)

        if access_token:
            request.data["token"] = access_token

        response = super().post(request, *args, **kwargs)

        response.data["detail"] = "Verified Access Token!"
        response.data["statusCode"] = response.status_code
        response.data["success"] = True
        response.data["data"] = {
            settings.AUTH_COOKIE_ACCESS_TOKEN_KEY: access_token, settings.AUTH_COOKIE_REFRESH_TOKEN_KEY: refresh_token
        }

        return response


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
