from django.contrib import admin
from authentication.models import TwoFactorAuthCodes, TopoPassword, CustomUser


admin.site.register(TwoFactorAuthCodes)
admin.site.register(TopoPassword)
admin.site.register(CustomUser)