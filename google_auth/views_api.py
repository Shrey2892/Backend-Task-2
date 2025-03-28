import os
import logging
import requests
import jwt  # Install with `pip install PyJWT`
from dotenv import load_dotenv
from django.utils.timezone import now, timedelta
from django.contrib.auth import login, logout
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from .models import CustomUser

load_dotenv()  # Load environment variables

logger = logging.getLogger(__name__)

# Google OAuth Credentials from .env
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")


### 🔹 Google Login API - Returns Auth URL ###
@api_view(["GET"])
@permission_classes([AllowAny])
def google_login_api(request):
    auth_url = (
        "https://accounts.google.com/o/oauth2/auth?"
        "response_type=code"
        f"&client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT_URI}"
        "scope=openid email profile https://www.googleapis.com/auth/userinfo.email "
        "https://www.googleapis.com/auth/userinfo.profile"
        "&access_type=offline"
        "&prompt=consent"
    )
    return Response({"auth_url": auth_url})


### 🔹 Google Callback API - Handles User Authentication ###
@api_view(["GET"])
@permission_classes([AllowAny])
def google_callbacks_api(request):
    code = request.GET.get("code")
    if not code:
        return Response({"error": "Authorization code missing"}, status=400)

    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }

    # 🔹 Fetch Access Token from Google
    try:
        response = requests.post(token_url, data=data)
        response.raise_for_status()
        token_info = response.json()
        logger.info(f"Token Response: {token_info}")
    except requests.RequestException as e:
        logger.error(f"Failed to fetch token: {e}")
        return Response({"error": "Failed to retrieve access token"}, status=500)

    access_token = token_info.get("access_token")
    refresh_token = token_info.get("refresh_token")
    expires_in = token_info.get("expires_in", 3600)
    id_token = token_info.get("id_token")

    # 🔹 Decode ID Token to Get Email & User Info
    try:
        decoded_id_token = jwt.decode(id_token, options={"verify_signature": False})
        email = decoded_id_token.get("email")
        logger.info(f"Decoded ID Token: {decoded_id_token}")
    except Exception as e:
        logger.error(f"Failed to decode ID token: {e}")
        return Response({"error": "Failed to decode ID token"}, status=500)

    # 🔹 Fetch User Info as Fallback (if email is missing)
    user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        user_response = requests.get(user_info_url, headers=headers)
        user_data = user_response.json()
        logger.info(f"Google User Info Response: {user_data}")
    except requests.RequestException as e:
        logger.error(f"Failed to fetch user info: {e}")
        return Response({"error": "Failed to retrieve user info"}, status=500)

    email = email or user_data.get("email")  # Ensure we have an email

    if not email:
        return Response({"error": "Email not provided by Google", "user_data": user_data}, status=400)

    # 🔹 Create or Update User
    user, created = CustomUser.objects.get_or_create(email=email, defaults={
        "username": user_data.get("name", "Google User"),
        "google_id": user_data.get("id"),
        "profile_image": user_data.get("picture"),
        "is_logged_in": True,
    })

    if not created:
        user.is_logged_in = True
        if refresh_token:
            user.refresh_token = refresh_token
        user.save()

    # 🔹 Login User and Set Session
    login(request, user)
    request.session["user_id"] = user.id
    request.session["is_authenticated"] = True
    request.session["expires_at"] = (now() + timedelta(seconds=expires_in)).isoformat()
    request.session.set_expiry(expires_in)

    return Response({
        "message": "Login successful",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "profile_image": user.profile_image,
        },
        "access_token": access_token,
        "expires_in": expires_in,
    })


@api_view(["GET"])
@permission_classes([AllowAny])
def google_callback_api(request):
    code = request.GET.get("code")
    if not code:
        return Response({"error": "Authorization code missing"}, status=400)

    # Exchange code for tokens
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }

    try:
        response = requests.post(token_url, data=token_data)
        response.raise_for_status()
        token_info = response.json()
        logger.info(f"Token Response: {token_info}")
    except requests.RequestException as e:
        logger.error(f"Failed to fetch token: {e}")
        return Response({"error": "Failed to retrieve access token"}, status=500)

    access_token = token_info.get("access_token")
    id_token = token_info.get("id_token")

    # Decode ID token
    try:
        decoded_id_token = jwt.decode(id_token, options={"verify_signature": False})
        email = decoded_id_token.get("email")
        logger.info(f"Decoded ID Token: {decoded_id_token}")
    except Exception as e:
        logger.error(f"Failed to decode ID token: {e}")
        return Response({"error": "Failed to decode ID token"}, status=500)

    # Fetch User Info as Fallback (if email is missing)
    user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        user_response = requests.get(user_info_url, headers=headers)
        user_data = user_response.json()
        email = user_data.get("email")
        logger.info(f"Google User Info Response: {user_data}")
    except requests.RequestException as e:
        logger.error(f"Failed to fetch user info: {e}")
        return Response({"error": "Failed to retrieve user info"}, status=500)

    email = email or user_data.get("email")  # Ensure we have an email

    # 🔴 Handle Missing Email Case 🔴
    if not email:
        logger.error("Google did not return an email address.")
        return Response({"error": "Email not provided by Google", "user_data": user_data}, status=400)

    # Create or Update User
    user, created = CustomUser.objects.get_or_create(email=email, defaults={
        "username": user_data.get("name", "Google User"),
        "google_id": user_data.get("id"),
        "profile_image": user_data.get("picture"),
        "is_logged_in": True,
    })

    if not created:
        user.is_logged_in = True
        user.save()

    login(request, user)

    return Response({
        "message": "Login successful",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "profile_image": user.profile_image,
        },
        "access_token": access_token,
    })





### 🔹 Google Logout API ###
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def google_logout_api(request):
    token = request.session.get("access_token")
    if token:
        requests.post("https://accounts.google.com/o/oauth2/revoke", params={"token": token})

    user_id = request.session.get("user_id")
    if user_id:
        CustomUser.objects.filter(id=user_id).update(is_logged_in=False)

    request.session.flush()
    logout(request)
    return Response({"message": "Logout successful"})


### 🔹 Get Authenticated User Info API ###
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user_info_api(request):
    user = request.user
    return Response({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "profile_image": user.profile_image,
        "is_logged_in": user.is_logged_in,
    })