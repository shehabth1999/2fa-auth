from django.urls import path, include

urlpatterns = [
    path('', include('authentication.web.urls')),
    path('api/', include('authentication.api.urls')),
]