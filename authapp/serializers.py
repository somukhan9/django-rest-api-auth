from rest_framework import serializers
from django.contrib.auth import get_user_model

from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from .utils import Util


User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(
        write_only=True, label="Confirm Password", style={"input_type": "password"})

    class Meta:
        model = User
        fields = ("id", "first_name", "last_name", "username",
                  "email", "password", "password2",)
        extra_kwargs = {
            "id": {
                "read_only": True,
            },
            "password": {
                "write_only": True,
                "style": {
                    "input_type": "password",
                },
            }
        }

    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.get("password2")

        if len(password) < 8:
            raise serializers.ValidationError(
                "Password should be at least of 8 characters!")

        if password != password2:
            raise serializers.ValidationError("Passwords did not match!")

        return attrs

    def create(self, validated_data):
        validated_data.pop("password2", None)

        return User.objects.create_user(**validated_data)


class LoginUserSerializer(serializers.Serializer):
    username_or_email = serializers.CharField(
        label="Username Or Email", required=True)
    password = serializers.CharField(
        style={"input_type": "password"}, label="Password", required=True)


class ChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(label="Password", required=True, style={
                                     "input_type": "password"}, write_only=True)
    password2 = serializers.CharField(
        label="Confirm Password", required=True, style={"input_type": "password"}, write_only=True)

    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.get("password2")

        user = self.context.get("user")

        if len(password) < 8:
            raise serializers.ValidationError(
                "Password should be at least of 8 characters!")

        if password != password2:
            raise serializers.ValidationError("Passwords did not match!")

        user.set_password(password)
        user.save()

        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255, write_only=True)

    def validate(self, attrs):
        email = attrs.get("email")
        user = User.objects.filter(email=email)

        if not user.exists():
            raise serializers.ValidationError("Invalid email address")

        user = user.first()

        encoded_uid = urlsafe_base64_encode(force_bytes(user.id))
        token = PasswordResetTokenGenerator().make_token(user)

        link = f"http://localhost:3000/reset-password/{encoded_uid}/{token}"

        print(link)

        # Send Email
        body = f"<h1>To reset your password click on the following link</h1><a href=\"{
            link}\">{link}</a>"
        data = {
            "subject": "Reset Password",
            "body": body,
            "to_email": user.email,
        }

        Util.send_email(data)

        return attrs


class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.get("password2")
        encoded_uid = self.context.get("uid")
        token = self.context.get("token")

        if len(password) < 8:
            raise serializers.ValidationError(
                "Password should be at lease of 8 characters!")

        if password != password2:
            raise serializers.ValidationError("Passwords did not match!")

        try:

            decoded_uid = smart_str(urlsafe_base64_decode(encoded_uid))

            user = User.objects.get(id=decoded_uid)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError(
                    "Token is not valid or expired!")

            user.set_password(password)

            user.save()

            return attrs

        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError("Token is not valid or expired!")
