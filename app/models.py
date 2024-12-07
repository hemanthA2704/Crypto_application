from pydantic import BaseModel
from typing import List
# Schema for input validation
class UserRequest(BaseModel):
    username: str
    password: str

class MessageRequest(BaseModel):
    username: str
    password: str  # A list of integers between 0 and 15
    message: List[int]
