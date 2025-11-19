import pyotp
import qrcode
import io
import base64
from typing import Tuple

class TOTPService:
    @staticmethod
    def generate_totp_secret() -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    @staticmethod
    def generate_qr_code(email: str, secret: str, issuer: str = "MyApp") -> str:
        """Generate QR code for TOTP setup"""
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=email,
            issuer_name=issuer
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    
    @staticmethod
    def verify_totp(secret: str, code: str) -> bool:
        """Verify TOTP code"""
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)
    
    @staticmethod
    def get_totp_setup(email: str) -> Tuple[str, str]:
        """Get TOTP secret and QR code"""
        secret = TOTPService.generate_totp_secret()
        qr_code = TOTPService.generate_qr_code(email, secret)
        return secret, qr_code