from pymongo import MongoClient
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Connect to MongoDB
client = MongoClient(os.getenv('MONGO_URI'))
db = client.get_default_database()

# Clear chat messages
result = db.chat_messages.delete_many({})
print(f"Deleted {result.deleted_count} chat messages")

# Close connection
client.close()