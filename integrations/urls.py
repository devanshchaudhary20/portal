from django.urls import path
from . import views

urlpatterns = [
    path('', views.landing_page, name='landing_page'),
    path('linkedin-auth/', views.authorize_linkedin, name='linkedin_auth'),
    path('linkedin-callback/', views.oauth2callback_linkedin, name='oauth2callback_linkedin'),
    path('post-on-linkedin/', views.post_on_linkedin, name='post_on_linkedin'),
    path('twitter-auth/', views.twitter_auth, name='twitter_auth'),
    path('twitter-callback/', views.twitter_callback, name='twitter_callback'),
    path('twitter-post-form/', views.twitter_post_form, name='twitter_post_form'),
    path('post-on-twitter/', views.post_on_twitter, name='post_on_twitter'),
    path('linkedin-post-form/', views.linkedin_post_form, name='linkedin_post_form'),
    path('cancel_scheduled_post/<int:post_id>/', views.cancel_scheduled_post, name='cancel_scheduled_post'),
    path('scheduled_post_cancelled/', views.scheduled_post_cancelled, name='scheduled_post_cancelled'),
]