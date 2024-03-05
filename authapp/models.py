from django.core.exceptions import ValidationError

from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager

# from django.db.models.signals import pre_save
# from django.dispatch import receiver


class UserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValidationError(
                "User must have an email.")

        if not username:
            raise ValidationError("User must have an username.")

        if len(password) < 8:
            raise ValidationError(
                "Password should be at least of 8 characters.")

        if self.model._default_manager.filter(email=self.normalize_email(email)).exists():
            # raise ValueError("A user with that email already exists!")
            print("A user with that email already exists.")
            raise ValidationError(
                "A user with " + f"email \"{email}\" already exists.")

        user = self.model(
            email=self.normalize_email(email),
            username=username,
            **extra_fields
        )

        user.set_password(password)

        user.save(using=self._db)

        return user

    def create_superuser(self, email, username, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(
            email=self.normalize_email(email),
            username=username,
            password=password,
            **extra_fields
        )


class User(AbstractUser):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(max_length=200, unique=True, error_messages={
        "unique": "A user with that email already exists."
    })
    profile_picture = models.ImageField(
        upload_to="media/users", null=True, blank=True)

    REQUIRED_FIELDS = ["email", "first_name", "last_name",]

    objects = UserManager()


# @receiver(pre_save, sender=User)
# def check_email(sender, instance, **kwargs):
#     if User.objects.filter(email=instance.email).exclude(username=instance.username).exists():
#         raise ValueError(f"A user with \"{instance.email}\" already exists.")


# @receiver(pre_save, sender=User)
# def check_username(sender, instance, **kwargs):
#     if User.objects.filter(username=instance.username).exclude(email=instance.email).exists():
#         raise ValueError(f"A user with \"" +
#                          instance.username + "\" already exists.")
