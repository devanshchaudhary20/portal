import base64
import json
import secrets
import logging

from django.shortcuts import redirect, render
from django.conf import settings
import requests

logger = logging.getLogger(__name__)


def authorize_linkedin(request):
    state = secrets.token_urlsafe(32),
    encoded_state = base64.urlsafe_b64encode(json.dumps(state).encode('utf-8')).decode('utf-8')

    authorization_url = (
        f"https://www.linkedin.com/oauth/v2/authorization?response_type=code"
        f"&client_id={settings.LINKEDIN_CLIENT_ID}&redirect_uri={settings.LINKEDIN_REDIRECT_URI}"
        f"&state={encoded_state}&scope=openid%20profile%20email%20w_member_social"
    )
    return redirect(authorization_url)


def oauth2callback_linkedin(request):
    code = request.GET.get('code')
    token_url = "https://www.linkedin.com/oauth/v2/accessToken"
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': settings.LINKEDIN_REDIRECT_URI,
        'client_id': settings.LINKEDIN_CLIENT_ID,
        'client_secret': settings.LINKEDIN_CLIENT_SECRET,
    }

    response = requests.post(token_url, data=token_data)
    access_token = response.json().get('access_token')

    # Save the access token in the session or database as per your need
    request.session['access_token'] = access_token

    return redirect('post_on_linkedin')


def get_linkedin_user_info(access_token):
    user_info_url = "https://api.linkedin.com/v2/userinfo"
    headers = {
        'Authorization': f'Bearer {access_token}',
    }

    response = requests.get(user_info_url, headers=headers)
    logger.info(f"User info status code: {response.status_code}")
    logger.info(f"User info response: {response.text}")

    if response.status_code == 200:
        return response.json()
    else:
        return None


def post_on_linkedin(request):
    access_token = request.session.get('access_token')
    user_info = get_linkedin_user_info(access_token)
    logger.info(f"User info: {user_info}")

    if not user_info:
        return render(request, 'integrations/post_failed.html', {'error': 'Failed to retrieve user information'})

    post_url = "https://api.linkedin.com/v2/ugcPosts"

    userId = user_info['sub']

    headers = {
        'Authorization': f'Bearer {access_token}',
        'X-Restli-Protocol-Version': '2.0.0',
        'Content-Type': 'application/json',
    }

    post_data = {
        "author": f"urn:li:person:" + userId,
        "lifecycleState": "PUBLISHED",
        "specificContent": {
            "com.linkedin.ugc.ShareContent": {
                "shareCommentary": {
                    "text": "Hello LinkedIn! This is a test post."
                },
                "shareMediaCategory": "NONE"
            }
        },
        "visibility": {
            "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
        }
    }

    response = requests.post(post_url, headers=headers, json=post_data)
    post_urn = response.json().get('id')

    return render(request, 'integrations/post_success.html', {'post_urn': post_urn})
