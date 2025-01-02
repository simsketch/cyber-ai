from enum import Enum
from typing import List, Dict, Optional
from datetime import datetime
from beanie import Document

class ReportType(str, Enum):
    SCAN = "scan"
    ASSESSMENT = "assessment"
    AUDIT = "audit"

class Report(Document):
    title: str
    type: str
    description: str
    scan_ids: List[str]
    user_id: str
    generated_at: datetime
    data: Dict
    markdown_content: str
    ai_summary: Optional[str] = None
    scan_duration: Optional[float] = None  # Duration of the scan in seconds
    health_score: Optional[int] = None  # Overall health score (0-100)
    health_rating: Optional[str] = None  # Rating based on health score (e.g., "Good", "Fair", "Poor")

    class Settings:
        name = "reports" 