from django import forms
from .models import Firm

class FirmRegistrationForm(forms.ModelForm):
    class Meta:
        model = Firm
        fields = ['name', 'geographic_area', 'ceo', 'linkedin_handle', 'twitter_handle']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'geographic_area': forms.TextInput(attrs={'class': 'form-control'}),
            'ceo': forms.TextInput(attrs={'class': 'form-control'}),
            'linkedin_handle': forms.TextInput(attrs={'class': 'form-control'}),
            'twitter_handle': forms.TextInput(attrs={'class': 'form-control'}),
        }
