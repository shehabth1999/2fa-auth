from django.urls import path, include
from authentication.api.views import CustomTokenObtainPairView, Enable_2fa, VerifyEnable_2fa, Verify_2fa, Disable_2fa
from rest_framework_simplejwt.views import TokenRefreshView


urlpatterns = [
    path('token/',              CustomTokenObtainPairView.as_view(),    name='token_obtain_pair'),
    path('token/refresh/',      TokenRefreshView.as_view(),             name='token_refresh'),
    path('enable-2fa/',         Enable_2fa.as_view(),                   name='enable_2fa_api'),
    path('enable-2fa/verify/',  VerifyEnable_2fa.as_view(),             name='enable_verify_2fa_api'),
    path('disable-2fa/',        Disable_2fa.as_view(),                  name='disable_2fa_api'),
    path('verify-2fa/',         Verify_2fa.as_view(),                   name='verify_2fa_api'),
]