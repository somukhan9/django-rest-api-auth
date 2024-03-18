from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError


class CustomJWTAuthentication(JWTAuthentication):
    def get_raw_token(self, request):

        header = self.get_header(request)
        if header:
            parts = header.split()
            if len(parts) == 2:
                return parts[1]

        # Check if the access token is provided in the cookies
        if 'access_token' in request.COOKIES:
            return request.COOKIES['access_token']

        return None

    def authenticate(self, request):
        raw_token = self.get_raw_token(request)
        if raw_token is None:
            return None

        try:
            validated_token = self.get_validated_token(raw_token)
            print(validated_token)
            return self.get_user(validated_token), validated_token
        except TokenError as ex:
            print("FROM TokenError")
            print(str(ex))
            pass
        except Exception as ex:
            print("Exception")
            print(str(ex))
            # raise ex

        return None

    pass
