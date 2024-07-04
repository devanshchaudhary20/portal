# firms/views.py
from django.shortcuts import render, redirect
from .forms import FirmRegistrationForm

def firm_registration(request):
    if request.method == 'POST':
        form = FirmRegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            return render(request, 'firms/registration_success.html')
    else:
        form = FirmRegistrationForm()
    return render(request, 'firms/firm_registration.html', {'form': form})
