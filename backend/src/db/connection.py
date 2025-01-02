import motor.motor_asyncio
from beanie import init_beanie
from models.scan import Scan
from models.user import User
from models.report import Report
import os
from dotenv import load_dotenv
import dns.resolver
import ssl
import logging
import asyncio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
        logger.info("Initializing MongoDB connection...")
        
        # Configure MongoDB client with proper settings
        _db_client = motor.motor_asyncio.AsyncIOMotorClient(
            MONGODB_URI,
            serverSelectionTimeoutMS=3000,  # More aggressive timeout
            connectTimeoutMS=5000,
            socketTimeoutMS=5000,
            tlsAllowInvalidCertificates=True,
            retryWrites=True,
            maxPoolSize=10,  # Reduced pool size
            minPoolSize=0,   # Start with no connections
            maxIdleTimeMS=15000,
            waitQueueTimeoutMS=3000,
            heartbeatFrequencyMS=10000,
            appname="cyber_ai_backend"
        )
        
        # Verify connection with timeout
        logger.info("Verifying MongoDB connection...")
        try:
            # Add timeout to server_info call
            await asyncio.wait_for(
                _db_client.server_info(),
                timeout=5.0  # 5 second timeout
            )
            logger.info("MongoDB connection verified successfully")
        except asyncio.TimeoutError:
            logger.error("Timeout while verifying MongoDB connection")
            raise
        except Exception as e:
            logger.error(f"Failed to verify MongoDB connection: {str(e)}")
            raise
        
        logger.info("Initializing Beanie ODM...")
        try:
            # Add timeout to init_beanie call
            await asyncio.wait_for(
                init_beanie(
                    database=_db_client[DB_NAME],
                    document_models=[
                        Scan,
                        User,
                        Report
                    ]
                ),
                timeout=5.0  # 5 second timeout
            )
            logger.info("Beanie ODM initialized successfully")
        except asyncio.TimeoutError:
            logger.error("Timeout while initializing Beanie ODM")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize Beanie ODM: {str(e)}")
            raise
            
        return _db_client
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {str(e)}")
        logger.error(f"Connection string used (redacted): {MONGODB_URI[:15]}...{MONGODB_URI[-15:]}")
        # Close client on error
        if _db_client:
            _db_client.close()
            _db_client = None
        raise

async def get_db():
    """Get database instance"""
    global _db_client
    if not _db_client:
        logger.info("No existing client, initializing new MongoDB connection")
        await init_db()
    return _db_client[DB_NAME] 