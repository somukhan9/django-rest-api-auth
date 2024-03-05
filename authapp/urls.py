from django.urls import path

from . import views

app_name = "authapp"


urlpatterns = [
    path("sign-up/", views.CreateUserView.as_view(), name="api.auth.sign-up"),
    path("login/", views.LoginUserAPIView.as_view(), name="api.auth.login"),
    path("logout/", views.Logout.as_view(), name="api.auth.logout"),
    path("refresh-token/", views.CustomTokenRefreshView.as_view(),
         name="api.auth.refresh_token"),
    path("profile/", views.ProfileAPIView.as_view(),
         name="api.auth.profile"),
    path("change-password/", views.ChangePasswordAPIView.as_view(),
         name="api.auth.change-password"),
    path("send-reset-password-email/",
         views.SendResetPasswordEmailAPIView.as_view(), name="api.auth.send-reset-password-email"),
    path("reset-password/<uid>/<token>/",
         views.ResetPasswordAPIView.as_view(), name="api.auth.reset-password")
]
