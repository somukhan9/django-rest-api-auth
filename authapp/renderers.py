import json
from rest_framework import status
from rest_framework.renderers import JSONRenderer


class AuthAppRenderer(JSONRenderer):
    charset = "utf-8"

    def render(self, data, accepted_media_type=None, renderer_context=None):
        response = ''

        status_code = getattr(renderer_context['response'], 'status_code',
                              status.HTTP_500_INTERNAL_SERVER_ERROR)

        if "ErrorDetail" in str(data):
            print("HELLO " + str(data))
            response = json.dumps(
                {"errors": data, "statusCode": status_code, "success": False})
        else:
            response = json.dumps(data)

        return response
