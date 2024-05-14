from rest_framework.permissions import BasePermission
from authentication.models import TotpPassword

class IsHaveNot2FAPermission(BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            return not request.user.factor_auth_at
        return False


class IsHave2FAPermission(BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            if request.user.factor_auth_at:
                return True
        token = request.data.get('token')
        if not token: return False
        try:
            user = TotpPassword.objects.get(token=token).user
            if user.factor_auth_at:
                return True
        except TotpPassword.DoesNotExist:
            return False

