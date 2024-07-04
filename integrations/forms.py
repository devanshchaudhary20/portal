from django import forms

class LinkedInPostForm(forms.Form):
    content = forms.CharField(label='Content', widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 4}))
    scheduled_at = forms.DateTimeField(label='Scheduled At', required=False, widget=forms.DateTimeInput(attrs={'class': 'form-control datetimepicker-input', 'placeholder': 'YYYY-MM-DD HH:MM'}))


class TwitterPostForm(forms.Form):
    content = forms.CharField(label='Content', widget=forms.Textarea)
    scheduled_at = forms.DateTimeField(label='Scheduled At', required=False, widget=forms.DateTimeInput(attrs={'class': 'form-control datetimepicker-input', 'placeholder': 'YYYY-MM-DD HH:MM'}))
