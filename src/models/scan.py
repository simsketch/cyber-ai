from datetime import datetime
from typing import Optional, List
from beanie import Document, Link
from pydantic import BaseModel, Field
from enum import Enum

class ScanStatus(str, Enum):
    QUEUED = "queued"
    IN_PROGRESS = "in-progress"
    COMPLETED = "completed"
    FAILED = "failed"

class VulnerabilitySeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Vulnerability(BaseModel):
    title: str
    description: str
    severity: str
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None

    def dict(self, *args, **kwargs):
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id
        }

class Scan(Document):
    target: str
    status: ScanStatus
    user_id: str  # Clerk user ID
    vulnerabilities: List[Vulnerability] = []
    total_vulnerabilities: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    scan_type: str = "network"
    scan_options: dict = {}
    progress: int = 0

    class Settings:
        name = "scans"
        indexes = [
            "status",
            "target",
            "user_id",
            "created_at",
            [("target", 1), ("created_at", -1)],
            [("user_id", 1), ("created_at", -1)]
        ]

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
        
    def dict(self, *args, **kwargs):
        # Get the default dict representation
        d = super().dict(*args, **kwargs)
        # Convert ObjectId to string
        d["id"] = str(self.id)
        return d 