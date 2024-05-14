from django.contrib import admin
from authentication.models import TwoFactorAuthCodes, TotpPassword, CustomUser


admin.site.register(TwoFactorAuthCodes)
admin.site.register(TotpPassword)
admin.site.register(CustomUser)