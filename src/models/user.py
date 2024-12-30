from datetime import datetime
from typing import Optional, List
from beanie import Document, Link
from pydantic import BaseModel, EmailStr

class User(Document):
    email: EmailStr
    clerk_id: str
    name: Optional[str] = None
    created_at: datetime = datetime.utcnow()
    last_login: Optional[datetime] = None
    settings: dict = {}
    
    class Settings:
        name = "users"
        indexes = [
            "email",
            "clerk_id",
            [("email", 1), ("created_at", -1)]
        ]

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        } 