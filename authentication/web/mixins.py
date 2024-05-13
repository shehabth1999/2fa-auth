from django.contrib.auth.mixins import UserPassesTestMixin
from django.core.exceptions import PermissionDenied
from authentication.models import CustomUser

class IsHaveNot2FA(UserPassesTestMixin):
    def test_func(self):
        if self.request.user.is_authenticated:
            return not self.request.user.factor_auth_at
        return False
    
class IsHave2FA(UserPassesTestMixin):
    def test_func(self):
        username = self.request.session.get('username', None)
        if username:
            user = CustomUser.objects.get(username=username)
            return user.factor_auth_at 
        return self.request.user.factor_auth_at 