from datetime import datetime
from typing import Optional, List, Dict, Any
from beanie import Document, Link
from pydantic import BaseModel, Field
from enum import Enum

class ReportType(str, Enum):
    VULNERABILITY = "vulnerability"
    SECURITY_POSTURE = "security_posture"
    COMPLIANCE = "compliance"
    INCIDENT = "incident"

class Report(Document):
    title: str
    type: ReportType
    description: str
    data: Dict[str, Any]
    markdown_content: Optional[str] = None
    ai_summary: Optional[str] = None
    user_id: str
    scan_ids: List[str]
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    
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