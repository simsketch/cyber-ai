from datetime import datetime
from typing import Optional, List
from beanie import Document, Link
from pydantic import BaseModel
from enum import Enum

class ReportType(str, Enum):
    VULNERABILITY = "vulnerability"
    SECURITY_POSTURE = "security_posture"
    COMPLIANCE = "compliance"
    INCIDENT = "incident"

class Report(Document):
    title: str
    type: ReportType
    description: Optional[str] = None
    generated_at: datetime = datetime.utcnow()
    data: dict = {}
    user_id: str  # Clerk user ID
    scan_ids: List[str] = []  # References to related scans
    tags: List[str] = []
    
    class Settings:
        name = "reports"
        indexes = [
            "type",
            "user_id",
            [("user_id", 1), ("generated_at", -1)]
        ]

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        } 