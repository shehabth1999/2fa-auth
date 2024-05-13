from django.urls import path, include
from .views import Enable_2fa, VerifyEnable_2fa, Verify_2fa, Success_2fa, LoginView, LogoutView, Disable_2fa

urlpatterns = [
    path('login/',              LoginView.as_view(),        name='login'),
    path('logout/',             LogoutView.as_view(),       name='logout'),
    path('enable-2fa/verify/',  VerifyEnable_2fa.as_view(), name='enable_verify_2fa'),
    path('enable-2fa/',         Enable_2fa.as_view(),       name='enable_2fa'),
    path('disable-2fa/',        Disable_2fa.as_view(),      name='disable_2fa'),
    path('verify-2fa/',         Verify_2fa.as_view(),       name='verify_2fa'),
    path('success/',            Success_2fa.as_view(),      name='success_2fa'),
]