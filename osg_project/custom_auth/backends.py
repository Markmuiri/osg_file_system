from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.db.models import Q
from rest_framework_simplejwt.authentication import JWTAuthentication

User = get_user_model()

class CustomJWTAuthentication(BaseBackend):
    """
    A custom authentication backend to integrate with the JWT system.
    This backend is used to authenticate a user when their token is valid,
    and also to retrieve the user object from the database.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        This method is required by Django's authentication system but
        is not used by Simple JWT. JWT authentication happens in the
        JWTAuthentication class, which we'll use in our views.
        We'll keep this method for completeness.
        """
        return None

    def get_user(self, user_id):
        """
        Retrieves a user instance from the database using their primary key.
        This is a crucial method for the session-based authentication flow.
        """
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def get_user_from_token(self, token):
        """
        This custom method will be used to get a user object from a JWT.
        We will use this in our views to ensure the user exists.
        """
        jwt_authenticator = JWTAuthentication()
        try:
            # Validate the token and get the validated_token object
            validated_token = jwt_authenticator.get_validated_token(token)
            # Get the user from the validated token
            return jwt_authenticator.get_user(validated_token)
        except Exception as e:
            # If token is invalid or expired, return None
            print(f"Token validation failed: {e}")
            return None

