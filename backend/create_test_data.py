import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database import SessionLocal, engine, Base
from app.models.tenant import Tenant
from app.models.user import User
from app.services.auth_service import AuthService

def create_test_data():
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    
    try:
        # Check if tenant already exists
        existing_tenant = db.query(Tenant).filter(Tenant.domain == "test-company").first()
        if not existing_tenant:
            # Create a test tenant
            tenant = Tenant(name="Test Company", domain="test-company")
            db.add(tenant)
            db.commit()
            db.refresh(tenant)
            print(f"Created tenant: {tenant.domain}")
        else:
            tenant = existing_tenant
            print(f"Using existing tenant: {tenant.domain}")
        
        # Check if user already exists
        existing_user = db.query(User).filter(
            User.email == "test@example.com",
            User.tenant_id == tenant.id
        ).first()
        
        if not existing_user:
            # Create a test user
            hashed_password = AuthService.get_password_hash("password123")
            user = User(
                email="test@example.com",
                hashed_password=hashed_password,
                tenant_id=tenant.id
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            print(f"Created user: {user.email}")
        else:
            user = existing_user
            print(f"Using existing user: {user.email}")
        
        print("\nTest data ready!")
        print(f"Tenant Domain: {tenant.domain}")
        print(f"User Email: {user.email}")
        print("Password: password123")
        print("\nYou can now:")
        print("1. Run the server: uvicorn app.main:app --reload --host 0.0.0.0 --port 8000")
        print("2. Open http://localhost:8000/docs for API documentation")
        print("3. Use the frontend at http://localhost:8000 (if you serve the HTML file)")
        
    except Exception as e:
        print(f"Error creating test data: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    create_test_data()