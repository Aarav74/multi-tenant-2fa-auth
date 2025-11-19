import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database import SessionLocal
from app.models.user import User
from app.services.totp_service import TOTPService

def test_2fa_setup():
    db = SessionLocal()
    
    try:
        # Get the first user
        user = db.query(User).first()
        if not user:
            print("No users found. Please run create_test_data.py first.")
            return
        
        print(f"Testing 2FA setup for user: {user.email}")
        
        # Generate TOTP secret and QR code
        secret, qr_code = TOTPService.get_totp_setup(user.email)
        
        print(f"Secret: {secret}")
        print(f"QR Code generated: {len(qr_code)} characters")
        
        # Test verification
        test_code = "123456"
        is_valid = TOTPService.verify_totp(secret, test_code)
        print(f"Test verification with {test_code}: {is_valid}")
        
        print("\n2FA setup test completed successfully!")
        
    except Exception as e:
        print(f"Error testing 2FA: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    test_2fa_setup()