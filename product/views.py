from rest_framework.decorators import (
    api_view,
    permission_classes,
    authentication_classes,
)

from rest_framework.response import Response
from rest_framework import status


@api_view(["GET"])
def home(request):
    return Response({"detail": "This is a private route"}, status=status.HTTP_200_OK)
