from django.urls import path
from . import views

urlpatterns = [
    path('linkedin-auth/', views.authorize_linkedin, name='linkedin_auth'),
    path('linkedin-callback/', views.oauth2callback_linkedin, name='linkedin_callback'),
    path('post-on-linkedin/', views.post_on_linkedin, name='post_on_linkedin'),
]
