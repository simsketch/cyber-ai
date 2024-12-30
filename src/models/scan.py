from datetime import datetime
from typing import Optional, List
from beanie import Document, Link
from pydantic import BaseModel
from enum import Enum

class ScanStatus(str, Enum):
    PENDING = "pending"
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
    severity: VulnerabilitySeverity
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    remediation: Optional[str] = None

class Scan(Document):
    target: str
    status: ScanStatus
    user_id: str  # Clerk user ID
    vulnerabilities: List[Vulnerability] = []
    total_vulnerabilities: int = 0
    started_at: datetime = datetime.utcnow()
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    scan_type: str = "network"
    scan_options: dict = {}

    class Settings:
        name = "scans"
        indexes = [
            "status",
            "target",
            "user_id",
            "started_at",
            [("target", 1), ("started_at", -1)],
            [("user_id", 1), ("started_at", -1)]
        ]

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        } 