import os
from pymongo import MongoClient
from dotenv import load_dotenv
load_dotenv()   

# MongoDB URI and client setup
MONGO_URI =os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["messages"]

# Collection to store user data and messages
messages_collection = db["messages"]
