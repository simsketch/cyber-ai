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

    class Settings:
        name = "reports" 