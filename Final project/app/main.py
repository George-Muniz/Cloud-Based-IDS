from fastapi import FastAPI
from pydantic import BaseModel
from ids_core.rules import analyze_event

app = FastAPI(title="Simple Cloud IDS")

class Event(BaseModel):
    src_ip: str
    path: str
    method: str
    payload: str

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/analyze")
def analyze(event: Event):
    result = analyze_event(event.dict())
    return {
        "event": event.dict(),
        "detection": result
    }
