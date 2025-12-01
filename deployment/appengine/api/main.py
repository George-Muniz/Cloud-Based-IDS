from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from ids_core.detector import detect
from ids_core.batch import analyze_gcs_csv
import os
import json

app = FastAPI(title="Cloud IDS")

class Event(BaseModel):
    src_ip: str
    dst_ip: str
    path: str
    method: str
    payload: str

_stats = {
    "total_events": 0,
    "alerts": 0,
    "errors": 0,
}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/analyze")
def analyze(event: Event):
    try:
        result = detect(event.dict())
        _stats["total_events"] += 1
        if result["is_intrusion"]:
            _stats["alerts"] += 1

        return {
            "event": event.dict(),
            "detection": result,
        }
    except Exception as e:
        _stats["errors"] += 1
        return {"error": str(e)}

@app.get("/analyze_batch")
def analyze_batch(gs_path: str = Query(..., description="gs://bucket/path.csv")):
    """
    Batch analyze a CSV stored in Google Cloud Storage.
    Example:
      /analyze_batch?gs_path=gs://ids-logs-george-thomas/sample_logs.csv
    """
    try:
        summary = analyze_gcs_csv(gs_path)
        _stats["total_events"] += summary.get("total_events", 0)
        _stats["alerts"] += summary.get("flagged", 0)
        return summary
    except Exception as e:
        _stats["errors"] += 1
        # raise HTTPException so App Engine returns a JSON 500, not HTML
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/summary")
def summary():
    return {
        "total_events": _stats["total_events"],
        "alerts": _stats["alerts"],
        "errors": _stats["errors"],
        "alert_ratio": (_stats["alerts"] / _stats["total_events"])
                        if _stats["total_events"] else 0.0,
    }

@app.get("/model_info")
def model_info():
    """
    Returns metadata about the trained ML model (algorithm, accuracy, confusion matrix, timestamp).
    """
    info_path = os.path.join(
        os.path.dirname(__file__), 
        "..",
        "ids_core",
        "model_info.json"
    )
    info_path = os.path.abspath(info_path)

    if not os.path.exists(info_path):
        raise HTTPException(status_code=404, detail="model_info.json not found")

    with open(info_path, "r") as f:
        data = json.load(f)

    return data

@app.get("/")
def root():
    return {"message": "IDS FastAPI is running"}

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    total = _stats["total_events"]
    alerts = _stats["alerts"]
    errors = _stats["errors"]
    ratio = (alerts / total) if total else 0.0

    html = f"""
    <html>
      <head>
        <title>Cloud IDS Dashboard</title>
        <style>
          body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #0b1020;
            color: #f0f0f0;
          }}
          .card {{
            background-color: #151a30;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
          }}
          h1 {{
            color: #5ad1ff;
          }}
          .metric-label {{
            font-size: 14px;
            color: #9ca3af;
          }}
          .metric-value {{
            font-size: 24px;
            font-weight: bold;
          }}
        </style>
      </head>
      <body>
        <h1>Cloud IDS - Summary</h1>
        <div class="card">
          <div class="metric-label">Total Events Processed</div>
          <div class="metric-value">{total}</div>
        </div>
        <div class="card">
          <div class="metric-label">Alerts Triggered</div>
          <div class="metric-value">{alerts}</div>
        </div>
        <div class="card">
          <div class="metric-label">Errors</div>
          <div class="metric-value">{errors}</div>
        </div>
        <div class="card">
          <div class="metric-label">Alert Ratio</div>
          <div class="metric-value">{ratio:.2%}</div>
        </div>
        <p>For JSON stats, see <code>/summary</code>.</p>
      </body>
    </html>
    """
    return HTMLResponse(content=html)
