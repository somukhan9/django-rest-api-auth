from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import User

# User = settings.AUTH_USER_MODEL


admin.site.register(User, UserAdmin)
