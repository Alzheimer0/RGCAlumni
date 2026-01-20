import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get MongoDB URI
mongo_uri = os.getenv('MONGO_URI')

if not mongo_uri:
    print("MONGO_URI not found in environment variables")
    sys.exit(1)

print(f"Connecting to MongoDB at: {mongo_uri}")

try:
    from pymongo import MongoClient
    
    # Connect to MongoDB
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    
    # Test connection
    client.server_info()
    print("Connected to MongoDB successfully")
    
    # Get database
    db = client.get_default_database()
    
    if db is None:
        print("Could not get default database")
        sys.exit(1)
    
    # Check if chat_messages collection exists
    collections = db.list_collection_names()
    print(f"Available collections: {collections}")
    
    if 'chat_messages' in collections:
        # Clear chat messages
        result = db.chat_messages.delete_many({})
        print(f"Deleted {result.deleted_count} chat messages from chat_messages collection")
    else:
        print("chat_messages collection not found")
        
    # Close connection
    client.close()
    print("Database connection closed")
    
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)