from django.db import models
from django.contrib.auth.models import BaseUserManager
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
import shortuuid
from django.utils import timezone

class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        """
        Create and return a regular user with an email, username, and password.
        """
        if not email:
            raise ValueError(_('The Email field must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        """
        Create and return a superuser with an email, username, and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))

        return self.create_user(email, username, password, **extra_fields)


class CustomUser(AbstractUser):
    factor_auth_at = models.DateTimeField(null=True, blank=True)

    objects = CustomUserManager()

    def enable_factor_auth(self):
        self.factor_auth_at = timezone.now()
        self.save()

    def disable_factor_auth(self):
        self.factor_auth_at = None
        self.save()


class TwoFactorAuthCodes(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='factorcodes', db_index=True)
    code = models.CharField(max_length=100)

    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ('user', 'code')

    def __str__(self) -> str:
        used = 'not used'
        if self.used_at :
            used = f'used at {self.used_at}'
        return f'{self.user.username} code | {used}'

    def clean(self):
        max_codes_per_user = 6
        if self.user.factorauth.count() >= max_codes_per_user:
            raise ValidationError(_('User already has the maximum number of authentication codes.'))

    @classmethod
    def create_codes(cls, user):
        cls.delete_codes(user)
        codes = []
        while len(codes) < 6:
            ucode = shortuuid.uuid()
            if ucode not in codes:
                codes.append(ucode)

        objects_to_create = [cls(code=code, user=user) for code in codes]
        cls.objects.bulk_create(objects_to_create)
        user.enable_factor_auth()
        return codes

    @classmethod
    def delete_codes(cls, user):
        cls.objects.filter(user=user).delete()
        return None

    @classmethod
    def get_codes(cls, user) -> list:
        return list(cls.objects.filter(user=user).values_list('code', flat=True))

class TopoPassword(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='TOTP')
    secret_key = models.CharField(max_length=50)      

    def __str__(self) -> str:
        return f'{self.user.username} secret key'