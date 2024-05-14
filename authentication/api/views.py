from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from authentication.utils import get_qrcode, generate_jwt_tokens
from authentication.api.permissions import IsHaveNot2FAPermission, IsHave2FAPermission
from pyotp import TOTP
from authentication.models import TotpPassword, TwoFactorAuthCodes
from rest_framework_simplejwt.views import TokenObtainPairView


class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if serializer.is_valid():
            username = request.data.get('username')
            password = request.data.get('password')
            user = authenticate(request, username=username, password=password)

            if user is not None and user.factor_auth_at:
                topo_password = user.TOTP 
                token = topo_password.generate_token()
                return Response({'token': token}, status=status.HTTP_200_OK)

        return super().post(request, *args, **kwargs)

class Enable_2fa(APIView):
    permission_classes = [IsHaveNot2FAPermission]
    def get(self, request):
        user = request.user
        qr_code_url , secret_key = get_qrcode(user)
        context = {
                    "qr_code_url":qr_code_url,
                    'secret_key':secret_key
                }
        return Response({'message':'True', 'data':context}, status=status.HTTP_200_OK)
    

class VerifyEnable_2fa(APIView):
    permission_classes = [IsHaveNot2FAPermission]
    def post(self, request):
        code = request.data.get('code')
        user = request.user
        totp = TOTP(user.TOTP.secret_key)
        if totp.verify(code):
            codes = TwoFactorAuthCodes.create_codes(user)
            return Response({'message': '2FA setup complete', 'reset_codes':codes }, status=status.HTTP_201_CREATED)
        else:
            return Response({'message': 'False'}, status=status.HTTP_404_NOT_FOUND)
    

class Verify_2fa(APIView):
    permission_classes = [IsHave2FAPermission]

    def post(self, request):
        code = request.data.get('code')
        token = request.data.get('token')
        try:
            user = TotpPassword.objects.get(token=token).user
        except TotpPassword.DoesNotExist:
            return Response({'message': 'Invalid token'}, status=status.HTTP_404_NOT_FOUND)
        
        totp = TOTP(user.TOTP.secret_key)
        if totp.verify(code):
            access_token, refresh_token = generate_jwt_tokens(user)
            user.TOTP.delete_token()
            return Response({'access_token': access_token, 'refresh_token': refresh_token}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Invalid code'}, status=status.HTTP_404_NOT_FOUND)
        

class Disable_2fa(APIView):
    permission_classes = [IsHave2FAPermission]

    def post(self, request):
        user = request.user
        totp = TOTP(user.TOTP.secret_key)
        code = request.POST.get('code')
        if totp.verify(code):
            TwoFactorAuthCodes.delete_codes(user)
            user.disable_factor_auth()
            TotpPassword.objects.filter(user=user).delete()
            return Response({'message':'2FA disabled .'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Invalid code .'}, status=status.HTTP_404_NOT_FOUND)