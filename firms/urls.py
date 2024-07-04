# firms/urls.py
from django.urls import path
from .views import firm_registration

urlpatterns = [
    path('register/', firm_registration, name='firm_registration'),
]
