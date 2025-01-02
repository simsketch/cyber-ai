import motor.motor_asyncio
from beanie import init_beanie
from models.scan import Scan
from models.user import User
from models.report import Report
import os
from dotenv import load_dotenv
import dns.resolver
import ssl

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URL")
if not MONGODB_URI:
    raise ValueError("MONGODB_URL environment variable is not set")

DB_NAME = os.getenv("DB_NAME", "cyber_ai")

# Global database client
_db_client = None

async def init_db():
    """Initialize database connection"""
    try:
        global _db_client
        # Configure MongoDB client with proper settings
        _db_client = motor.motor_asyncio.AsyncIOMotorClient(
            MONGODB_URI,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=20000,
            socketTimeoutMS=20000,
            tlsAllowInvalidCertificates=True,  # Don't verify SSL certificate
            retryWrites=True,
            maxPoolSize=50,
            minPoolSize=10,
            maxIdleTimeMS=50000,
            waitQueueTimeoutMS=5000
        )
        
        # Verify connection
        await _db_client.server_info()
        
        await init_beanie(
            database=_db_client[DB_NAME],
            document_models=[
                Scan,
                User,
                Report
            ]
        )
        return _db_client
    except Exception as e:
        print(f"Failed to connect to MongoDB: {str(e)}")
        raise

async def get_db():
    """Get database instance"""
    global _db_client
    if not _db_client:
        await init_db()
    return _db_client[DB_NAME] 