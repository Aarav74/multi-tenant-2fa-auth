from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import auth
from app.database import engine, Base

app = FastAPI(
    title="Multi-Tenant 2FA Authentication API",
    description="Secure authentication system with 2FA support",
    version="1.0.0"
)

# CORS configuration - UPDATED
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",  # VS Code Live Server
        "http://localhost:3000",   # React dev server
        "http://localhost:8080",   # Common frontend ports
        "http://localhost:5500",   # Alternative Live Server port
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)

@app.on_event("startup")
async def startup_event():
    # Create tables
    Base.metadata.create_all(bind=engine)

@app.get("/")
def root():
    return {
        "message": "Multi-Tenant 2FA Authentication API",
        "docs": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)