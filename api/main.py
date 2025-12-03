from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from ids_core.detector import detect
from ids_core.batch import analyze_gcs_csv
import os
import logging
import json


app = FastAPI(title="Cloud IDS")

# Simple logger; messages will propagate to the root logger,
# which App Engine / uvicorn already configure to go to stdout.
logger = logging.getLogger("ids_logger")
logger.setLevel(logging.INFO)


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

        try:
            single_summary = {
                "log_type": "IDS_SINGLE_EVENT",
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "path": event.path,
                "method": event.method,
                "is_intrusion": result.get("is_intrusion"),
                "score": result.get("score"),
            }
            logger.info(json.dumps(single_summary))
        except Exception:
            # Don't break the API if logging fails
            pass

        return {
            "event": event.dict(),
            "detection": result,
        }
    except Exception as e:
        _stats["errors"] += 1
        # Log the error as well
        logger.error(json.dumps({
            "log_type": "IDS_ERROR",
            "scope": "single_event",
            "error": str(e),
        }))
        return {"error": str(e)}


@app.get("/analyze_batch")
def analyze_batch(gs_path: str = Query(..., description="gs://bucket/path.csv")):
    """
    Batch analyze a CSV stored in Google Cloud Storage.
    Example:
      /analyze_batch?gs_path=gs://ids-logs-george-thomas/sample_logs.csv
    """
    try:
        # 1) Run your existing batch logic
        summary = analyze_gcs_csv(gs_path)

        # 2) Update in-memory stats (unchanged)
        _stats["total_events"] += summary.get("total_events", 0)
        _stats["alerts"] += summary.get("flagged", 0)

        # 3) Log a structured summary line for Cloud Logging / Monitoring
        try:
            log_payload = {
                "log_type": "IDS_RESULTS",
                "dataset": gs_path,
                "total_events": summary.get("total_events"),
                "flagged": summary.get("flagged"),
                "flagged_ratio": summary.get("flagged_ratio"),
                "skipped": summary.get("skipped"),
            }
            logger.info(json.dumps(log_payload))
        except Exception:
            # If logging fails, we still want to return the API response
            pass

        # 4) Return the full summary as before
        return summary
    except Exception as e:
        _stats["errors"] += 1
        logger.error(json.dumps({
            "log_type": "IDS_ERROR",
            "scope": "batch",
            "dataset": gs_path,
            "error": str(e),
        }))
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