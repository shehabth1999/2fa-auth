from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from authentication.web.views import HomePage

urlpatterns = [
    path('', HomePage.as_view(), name='home'),
    path('admin/', admin.site.urls),
    path('auth/', include('authentication.urls')),

]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
