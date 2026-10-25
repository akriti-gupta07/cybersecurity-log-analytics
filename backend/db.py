import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGO_DB", "cybersecurity_db")
COLLECTION_NAME = os.getenv("MONGO_COLLECTION", "network_logs")

_client = None

def get_collection():
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
    _client.admin.command("ping")
    return _client[DB_NAME][COLLECTION_NAME]
