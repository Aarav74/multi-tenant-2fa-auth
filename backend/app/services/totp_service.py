import pyotp
import qrcode
import io
import base64
from typing import Tuple
import logging
import time

logger = logging.getLogger(__name__)

class TOTPService:
    @staticmethod
    def generate_totp_secret() -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    @staticmethod
    def generate_qr_code(email: str, secret: str, issuer: str = "MyApp") -> str:
        """Generate QR code for TOTP setup"""
        try:
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=email,
                issuer_name=issuer
            )
            
            logger.info(f"Generated TOTP URI for {email}: {totp_uri[:50]}...")
            
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
        except Exception as e:
            logger.error(f"Error generating QR code for {email}: {e}")
            raise
    
    @staticmethod
    def verify_totp(secret: str, code: str) -> bool:
        """Verify TOTP code with better error handling"""
        try:
            if not secret or not code:
                logger.error("Missing secret or code for TOTP verification")
                return False
            
            # Clean the code (remove spaces, etc.)
            clean_code = str(code).strip().replace(" ", "")
            
            if len(clean_code) != 6 or not clean_code.isdigit():
                logger.error(f"Invalid TOTP code format: {code} (cleaned: {clean_code})")
                return False
            
            totp = pyotp.TOTP(secret)
            
            # Try current time and one time step before/after (for clock drift)
            result = totp.verify(clean_code, valid_window=1)
            
            logger.info(f"TOTP verification: secret={secret[:10]}..., code={clean_code}, result={result}")
            return result
            
        except Exception as e:
            logger.error(f"Error verifying TOTP: {e}")
            return False
    
    @staticmethod
    def get_totp_setup(email: str) -> Tuple[str, str]:
        """Get TOTP secret and QR code"""
        secret = TOTPService.generate_totp_secret()
        qr_code = TOTPService.generate_qr_code(email, secret)
        return secret, qr_code
    
    @staticmethod
    def get_current_totp_code(secret: str) -> str:
        """Get current TOTP code for debugging"""
        try:
            if not secret:
                return "No secret"
            totp = pyotp.TOTP(secret)
            return totp.now()
        except Exception as e:
            logger.error(f"Error getting current TOTP code: {e}")
            return "Error"
    
    @staticmethod
    def get_time_remaining() -> int:
        """Get seconds remaining in current TOTP period"""
        return 30 - (int(time.time()) % 30)