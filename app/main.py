from fastapi import FastAPI
from app.routes import router

app = FastAPI()

# Include the router for the application
app.include_router(router)

@app.get("/")
async def root():
    return {"message": "Welcome to the FastAPI Message App"}
