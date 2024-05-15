from pyotp import TOTP
from authentication.models import TotpPassword, TwoFactorAuthCodes
from authentication.utils import get_qrcode
from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm
from django.views import View
from authentication.models import CustomUser
from django.shortcuts import get_object_or_404
from django.contrib.auth.mixins import LoginRequiredMixin
from authentication.web.mixins import IsHave2FA , IsHaveNot2FA
from django.views.generic import TemplateView
from django.views.decorators.cache import cache_page
from django.utils.decorators import method_decorator


class Enable_2fa(IsHaveNot2FA, View):
    @method_decorator(cache_page(100))
    def get(self, request):
        user = request.user
        qr_code_url , secret_key = get_qrcode(user)
        context = {
                    "qr_code_url":qr_code_url,
                    'secret_key':secret_key
                }
        return render(request, template_name='authentication/enable_2fa.html', context=context)
    

class VerifyEnable_2fa(IsHaveNot2FA, View):
    template_name = 'authentication/verify_2fa.html'
    def post(self, request):
        totp = TOTP(TotpPassword.objects.get(user=request.user).secret_key)
        code = request.POST.get('code')
        if totp.verify(code):
            TwoFactorAuthCodes.create_codes(request.user)
            messages.success(request, f"You Enabeld 2FA with user , {request.user.username}.")
            return redirect('success_2fa')
        else:
            error_message = "Invalid TOTP code. Please try again."
            return render(request, self.template_name , {'error_message': error_message})
    def get(self, request):
        if request.user.is_authenticated:
            return redirect('home')
        return render(request, self.template_name)


class Verify_2fa(IsHave2FA, View):
    template_name = 'authentication/verify_2fa.html'
    def post(self, request):
        username = request.session.get('username', None)
        if not username:
            return redirect('login')
        user = get_object_or_404(CustomUser, username=username)
        totp = TOTP(TotpPassword.objects.get(user=user).secret_key)
        code = request.POST.get('code')
        if totp.verify(code):
            login(request, user)
            messages.success(request, f"Welcome back, {username}.")
            return redirect('home')
        else:
            error_message = "Invalid TOTP code. Please try again."
            return render(request,self.template_name , {'error_message': error_message})
    def get(self, request):
        if request.user.is_authenticated:
            return redirect('home')
        return render(request, self.template_name)


class Success_2fa(IsHave2FA, LoginRequiredMixin, View):
    def get(self, request):
        codes = TwoFactorAuthCodes.get_codes(request.user)
        return render(request, 'authentication/success_2fa.html', context={'codes': codes})


class Disable_2fa(IsHave2FA, LoginRequiredMixin, View):
    template_name = 'authentication/verify_2fa.html'
    def get(self, request):
        return render(request, self.template_name)
    
    def post(self, request):
        user = request.user
        totp = TOTP(TotpPassword.objects.get(user=user).secret_key)
        code = request.POST.get('code')
        if totp.verify(code):
            TwoFactorAuthCodes.delete_codes(user)
            user.disable_factor_auth()
            TotpPassword.objects.filter(user=user).delete()
        return render(request, 'authentication/disable_2fa.html')  
        

class LoginView(View):
    template_name = 'authentication/login.html'

    def get(self, request):
        if request.user.is_authenticated:
            return redirect('home')
        form = AuthenticationForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.factor_auth_at:   
                    request.session['username'] = user.username
                    return redirect('verify_2fa')
                else:
                    login(request, user)
                    messages.success(request, f"Welcome back, {username}.")
                    return redirect('home')
            else:
                messages.error(request, "Invalid username or password.")
        return render(request, self.template_name, {'form': form})

class LogoutView(LoginRequiredMixin, View):
    def post(self, request):
        logout(request)
        messages.info(request, "You have been logged out.")
        return redirect('login')

class HomePage(View):
    def get(self, request):
        return render(request, 'authentication/homepage.html')
