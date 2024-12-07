from passlib.context import CryptContext
from fastapi import HTTPException, APIRouter
from app.config import messages_collection
from app.models import UserRequest,MessageRequest
from app.cipher import enc64, dec64  # Import encryption and decryption functions
import random
from typing import List
from dotenv import load_dotenv
import os
router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
load_dotenv()   
KEY=list(map(int,os.getenv("KEY").split(" ")))
@router.post("/get-messages")
async def get_messages(user: UserRequest):
    # Check if the username exists in the database
    user_data = messages_collection.find_one({"username": user.username})
    
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify the provided password
    if not pwd_context.verify(user.password, user_data["password"]):
        raise HTTPException(status_code=401, detail="Invalid password")
    
    # Retrieve and decrypt messages
    encrypted_messages = user_data.get("messages", [])
    decrypted_messages = [dec64(msg, KEY, 28, print_details=False) for msg in encrypted_messages]
    
    return {"username": user.username, "messages": decrypted_messages}


@router.post("/create-user")
async def create_user(user: UserRequest):
    # Check if the username already exists
    existing_user = messages_collection.find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    # Hash the user's password
    hashed_password = pwd_context.hash(user.password)

    # Create the new user
    new_user = {
        "username": user.username,
        "password": hashed_password,  # Store the hashed password
        "messages": []  # Start with an empty messages list
    }
    
    # Insert the new user into the database
    messages_collection.insert_one(new_user)

    return {"message": "User created successfully"}

@router.post("/send-message")
async def send_message(request: MessageRequest):
    """
    Allow authenticated users to send a message in the form of a list.
    Messages are encrypted and stored in the database.
    """
    # Check if the user exists in the database
    user_data = messages_collection.find_one({"username": request.username})
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")

    # Verify the provided password
    if not pwd_context.verify(request.password, user_data["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Encrypt the message list
    encrypted_message = enc64(request.message, KEY, 28, print_details=False)

    # Add the encrypted message to the user's stored messages
    messages_collection.update_one(
        {"username": request.username},
        {"$push": {"messages": encrypted_message}}
    )

    return {"message": "Message sent successfully", "encrypted_message": encrypted_message}
