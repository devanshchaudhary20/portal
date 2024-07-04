import base64
import hashlib
import json
import secrets
import logging

from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils import timezone
from .models import ScheduledPost
from .forms import LinkedInPostForm, TwitterPostForm
import requests
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404

logger = logging.getLogger(__name__)


def generate_code_verifier():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

def generate_code_challenge(code_verifier):
    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(code_challenge).decode('utf-8').rstrip('=')

def landing_page(request):
    state = secrets.token_urlsafe(32)
    encoded_state = base64.urlsafe_b64encode(json.dumps(state).encode('utf-8')).decode('utf-8')

    linkedin_authorization_url = (
        f"https://www.linkedin.com/oauth/v2/authorization?response_type=code"
        f"&client_id={settings.LINKEDIN_CLIENT_ID}&redirect_uri={settings.LINKEDIN_REDIRECT_URI}"
        f"&state={encoded_state}&scope=openid%20profile%20w_member_social%20email"
    )

    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    request.session['code_verifier'] = code_verifier

    twitter_authorization_url = (
        f"https://twitter.com/i/oauth2/authorize?response_type=code"
        f"&client_id={settings.TWITTER_CLIENT_ID}&redirect_uri={settings.TWITTER_REDIRECT_URI}"
        f"&scope=tweet.read tweet.write users.read offline.access&state={state}"
        f"&code_challenge={code_challenge}&code_challenge_method=S256"
    )

    context = {
        'linkedin_authorization_url': linkedin_authorization_url,
        'twitter_authorization_url': twitter_authorization_url,
    }

    return render(request, 'integrations/landing_page.html', context)

def authorize_linkedin(request):
    state = secrets.token_urlsafe(32)
    encoded_state = base64.urlsafe_b64encode(json.dumps(state).encode('utf-8')).decode('utf-8')

    authorization_url = (
        f"https://www.linkedin.com/oauth/v2/authorization?response_type=code"
        f"&client_id={settings.LINKEDIN_CLIENT_ID}&redirect_uri={settings.LINKEDIN_REDIRECT_URI}"
        f"&state={encoded_state}&scope=openid%20profile%20w_member_social%20email"
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
    request.session['linkedin_access_token'] = access_token

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


def linkedin_post_form(request):
    form = LinkedInPostForm()
    return render(request, 'integrations/linkedin_post_form.html', {'form': form})


def post_on_linkedin(request):
    if request.method == 'POST':
        access_token = request.session.get('linkedin_access_token')
        if not access_token:
            return redirect('linkedin_auth')

        content = request.POST.get('content')
        scheduled_at_str = request.POST.get('scheduled_at')
        scheduled_at = None

        if scheduled_at_str:
            scheduled_at = timezone.datetime.strptime(scheduled_at_str, '%Y-%m-%d %H:%M')
            scheduled_at = timezone.make_aware(scheduled_at)

        if scheduled_at and scheduled_at > timezone.now():
            scheduled_post = ScheduledPost.objects.create(
                platform='linkedin',
                content=content,
                scheduled_at=scheduled_at,
                status='scheduled',
                access_token=access_token
            )

            request.session['scheduled_linkedin_post'] = {
                'content': content,
                'scheduled_at': scheduled_at_str,
            }

            return render(request, 'integrations/scheduled_confirmation.html', {
                'scheduled_at': scheduled_at_str,
                'content': content,
                'post_id': scheduled_post.id
            })

        # If immediate post or scheduled time is past, proceed with immediate post
        return post_on_linkedin_without_schedule(request)

    form = LinkedInPostForm()
    return render(request, 'integrations/linkedin_post_form.html', {'form': form})


def post_on_linkedin_without_schedule(request):
    access_token = request.session.get('linkedin_access_token')
    user_info = get_linkedin_user_info(access_token)
    logger.info(f"User info: {user_info}")
    content = request.POST.get('content')

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
                    "text": content
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


def post_on_linkedin_now(post):
    access_token = post.access_token

    user_info = get_linkedin_user_info(access_token)
    if not user_info:
        logger.error("Failed to retrieve user info with access token.")
        return

    userid = user_info.get('sub')
    if not userid:
        logger.error("User ID not found in user info.")
        return

    headers = {
        'Authorization': f'Bearer {access_token}',
        'X-Restli-Protocol-Version': '2.0.0',
        'Content-Type': 'application/json',
    }

    post_data = {
        "author": f"urn:li:person:" + userid,
        "lifecycleState": "PUBLISHED",
        "specificContent": {
            "com.linkedin.ugc.ShareContent": {
                "shareCommentary": {
                    "text": post.content
                },
                "shareMediaCategory": "NONE"
            }
        },
        "visibility": {
            "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
        }
    }

    response = requests.post("https://api.linkedin.com/v2/ugcPosts", headers=headers, json=post_data)
    if response.status_code == 201:
        logger.info(f"Successfully posted to LinkedIn. Post ID: {response.json().get('id')}")
    else:
        logger.error(f"Failed to post to LinkedIn: {response.status_code} {response.text}")


def cancel_scheduled_post(request, post_id):
    post = get_object_or_404(ScheduledPost, id=post_id)
    post.status = 'cancelled'
    post.save()
    return HttpResponseRedirect(reverse('scheduled_post_cancelled'))


def scheduled_post_cancelled(request):
    return render(request, 'integrations/scheduled_post_cancelled.html')


def twitter_auth(request):
    state = secrets.token_urlsafe(32)
    encoded_state = base64.urlsafe_b64encode(json.dumps(state).encode('utf-8')).decode('utf-8')
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    request.session['code_verifier'] = code_verifier

    redirect_uri = settings.TWITTER_REDIRECT_URI

    twitter_auth_url = (
        f"https://twitter.com/i/oauth2/authorize?response_type=code"
        f"&client_id={settings.TWITTER_CLIENT_ID}&redirect_uri={redirect_uri}"
        f"&scope=tweet.read tweet.write users.read offline.access&state={encoded_state}"
        f"&code_challenge={code_challenge}&code_challenge_method=S256"
    )

    return redirect(twitter_auth_url)

def twitter_callback(request):
    code = request.GET.get('code')
    code_verifier = request.session.get('code_verifier')
    token_url = 'https://api.twitter.com/2/oauth2/token'
    redirect_uri = settings.TWITTER_REDIRECT_URI

    client_credentials = f"{settings.TWITTER_CLIENT_ID}:{settings.TWITTER_CLIENT_SECRET}"
    client_credentials_b64 = base64.b64encode(client_credentials.encode()).decode()

    token_headers = {
        'Authorization': f'Basic {client_credentials_b64}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'client_id': settings.TWITTER_CLIENT_ID,
        'client_secret': settings.TWITTER_CLIENT_SECRET,
        'code_verifier': code_verifier,
    }


    response = requests.post(token_url, headers=token_headers, data=token_data)

    if response.status_code != 200:
        logger.error(f"Error fetching token: {response.text}")
        return render(request, 'integrations/post_failed.html', {'error': 'Error fetching token'})

    access_token = response.json().get('access_token')
    request.session['twitter_access_token'] = access_token

    return redirect('twitter_post_form')

def twitter_post_form(request):
    form = TwitterPostForm()
    return render(request, 'integrations/twitter_post_form.html', {'form': form})


def post_on_twitter(request):
    if request.method == 'POST':
        access_token = request.session.get('twitter_access_token')
        if not access_token:
            return redirect('twitter_auth')

        content = request.POST.get('content')
        scheduled_at_str = request.POST.get('scheduled_at')
        scheduled_at = None

        if scheduled_at_str:
            scheduled_at = timezone.datetime.strptime(scheduled_at_str, '%Y-%m-%d %H:%M')
            scheduled_at = timezone.make_aware(scheduled_at)

        if scheduled_at and scheduled_at > timezone.now():
            scheduled_post = ScheduledPost.objects.create(
                platform='twitter',
                content=content,
                scheduled_at=scheduled_at,
                status='scheduled',
                access_token=access_token
            )

            request.session['scheduled_twitter_post'] = {
                'content': content,
                'scheduled_at': scheduled_at_str,
            }

            return render(request, 'integrations/scheduled_confirmation.html', {
                'scheduled_at': scheduled_at_str,
                'content': content,
                'post_id': scheduled_post.id
            })

        # If immediate post or scheduled time is past, proceed with immediate post
        return post_on_twitter_without_schedule(request)

    form = TwitterPostForm()
    return render(request, 'integrations/twitter_post_form.html', {'form': form})


def post_on_twitter_now(post):
    access_token = post.access_token
    tweet_url = "https://api.twitter.com/2/tweets"

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    post_data = {
        "text": post.content
    }

    response = requests.post(tweet_url, headers=headers, json=post_data)

    if response.status_code == 201:
        logger.info(f"Successfully posted to Twitter. Tweet ID: {response.json().get('data', {}).get('id')}")
    else:
        logger.error(f"Failed to post to Twitter: {response.status_code} {response.text}")


def post_on_twitter_without_schedule(request):
    if request.method == 'POST':
        access_token = request.session.get('twitter_access_token')
        if not access_token:
            return redirect('twitter_auth')  # Redirect to authorization if access token is not available

        content = request.POST.get('content')
        tweet_url = "https://api.twitter.com/2/tweets"

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        post_data = {
            "text": content
        }

        response = requests.post(tweet_url, headers=headers, json=post_data)

        if response.status_code == 201:
            return render(request, 'integrations/post_success.html', {'post_urn': response.json().get('data', {}).get('id')})
        else:
            return render(request, 'integrations/post_failed.html', {'error': 'Failed to post on Twitter'})

    return redirect('twitter_post_form')
