from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from ids_core.detector import detect
from ids_core.batch import analyze_batch as run_batch_analysis
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

# Global single-event stats
_stats = {
    "total_events": 0,
    "alerts": 0,
    "errors": 0,
}

# Global batch stats (for /summary endpoint)
_batch_stats = {
    "last_dataset": None,
    "last_total_events": 0,
    "last_flagged": 0,
    "last_flagged_ratio": 0.0,
    "last_skipped": 0,
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
        # For single-event we keep the old behaviour (no HTTPException)
        return {"error": str(e)}


@app.get("/analyze_batch")
def analyze_batch(gs_path: str = Query(..., description="gs://bucket/path.csv")):
    """
    Batch analyze a CSV stored in Google Cloud Storage.
    Example:
      /analyze_batch?gs_path=gs://ids-logs-george-thomas/sample_logs.csv
    """
    try:
        # 1) Run your existing batch logic (note: using the aliased core function)
        summary = run_batch_analysis(gs_path)

        # 2) Update in-memory stats
        _stats["total_events"] += summary.get("total_events", 0)
        _stats["alerts"] += summary.get("flagged", 0)
        # 2b) Record last batch summary for /summary endpoint
        _batch_stats["last_dataset"] = gs_path
        _batch_stats["last_total_events"] = summary.get("total_events", 0)
        _batch_stats["last_flagged"] = summary.get("flagged", 0)
        _batch_stats["last_flagged_ratio"] = summary.get("flagged_ratio", 0.0)
        _batch_stats["last_skipped"] = summary.get("skipped", 0)


        # 3) Build a structured summary line
        log_payload = {
            "log_type": "IDS_RESULTS",
            "dataset": gs_path,
            "total_events": summary.get("total_events"),
            "flagged": summary.get("flagged"),
            "flagged_ratio": summary.get("flagged_ratio"),
            "skipped": summary.get("skipped"),
        }

        # 4) Print to stdout so App Engine definitely captures it
        print("IDS_RESULTS_LOG " + json.dumps(log_payload), flush=True)

        # still log via logging module too
        try:
            logger.info("IDS_RESULTS_LOG " + json.dumps(log_payload))
        except Exception:
            pass

        # 5) Return the full summary as before
        return summary

    except HTTPException as e:
        # If something already raised an HTTPException, just log and re-raise
        _stats["errors"] += 1
        error_payload = {
            "log_type": "IDS_ERROR",
            "scope": "batch",
            "dataset": gs_path,
            "error": str(e.detail),
        }
        print("IDS_RESULTS_ERROR " + json.dumps(error_payload), flush=True)
        try:
            logger.error("IDS_RESULTS_ERROR " + json.dumps(error_payload))
        except Exception:
            pass
        raise e

    except Exception as e:
        _stats["errors"] += 1

        error_payload = {
            "log_type": "IDS_ERROR",
            "scope": "batch",
            "dataset": gs_path,
            "error": str(e),
        }
        print("IDS_RESULTS_ERROR " + json.dumps(error_payload), flush=True)
        try:
            logger.error("IDS_RESULTS_ERROR " + json.dumps(error_payload))
        except Exception:
            pass

        # raise HTTPException so App Engine returns a JSON 500, not HTML
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/summary")
def summary():
    alert_ratio = (
        _stats["alerts"] / _stats["total_events"]
        if _stats["total_events"] else 0.0
    )

    return {
        "total_events": _stats["total_events"],
        "alerts": _stats["alerts"],
        "errors": _stats["errors"],
        "alert_ratio": alert_ratio,
        "last_batch": _batch_stats,
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
