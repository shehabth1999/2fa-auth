import pyotp, qrcode, io, os
import qrcode
from authentication.models import TotpPassword
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken


def get_qrcode(user):
    TotpPassword.objects.filter(user=user).delete()
    totp_secret = pyotp.random_base32()
    TotpPassword.objects.create(user=user, secret_key=totp_secret)
    otp_auth_url = pyotp.totp.TOTP(totp_secret).provisioning_uri(user.username, issuer_name='Django')
    img = qrcode.make(otp_auth_url)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)

    filename = f"{user.username}_qr_code.png"
    qr_code_path = os.path.join(settings.MEDIA_ROOT, filename)

    with open(qr_code_path, 'wb') as f:
        f.write(buffer.getvalue())
    
    # Construct the URL of the QR code image
    qr_code_url = os.path.join(settings.MEDIA_URL, filename)

    return qr_code_url, totp_secret


def generate_qr_code(request):
    # Facebook URL
    facebook_url = "https://maps.app.goo.gl/Ruru9mWwnxLW5XT76"

    # Create QR code instance
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    # Add Facebook URL to the QR code
    qr.add_data(facebook_url)
    qr.make(fit=True)

    # Create image from the QR code
    img = qr.make_image(fill_color="#0074D9", back_color="white")

    # Save the image to the media directory
    media_root = settings.MEDIA_ROOT
    img_path = os.path.join(media_root, 'qr_codes', 'elquser.png')
    img.save(img_path, format="PNG")

    # Return the URL of the saved image
    img_url = os.path.join(settings.MEDIA_URL, 'qr_codes', 'elquser.png')
    return img_url


def generate_jwt_tokens(user):
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    refresh_token = str(refresh)
    return access_token, refresh_token
