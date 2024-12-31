import motor.motor_asyncio
from beanie import init_beanie
from models.scan import Scan
from models.user import User
from models.report import Report
import os
from dotenv import load_dotenv

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URL")
if not MONGODB_URI:
    raise ValueError("MONGODB_URL environment variable is not set")

DB_NAME = os.getenv("DB_NAME", "cyber_ai")

async def init_db():
    """Initialize database connection"""
    try:
        client = motor.motor_asyncio.AsyncIOMotorClient(
            MONGODB_URI,
            serverSelectionTimeoutMS=5000
        )
        # Verify connection
        await client.server_info()
        
        await init_beanie(
            database=client[DB_NAME],
            document_models=[
                Scan,
                User,
                Report
            ]
        )
        return client
    except Exception as e:
        print(f"Failed to connect to MongoDB: {str(e)}")
        raise 