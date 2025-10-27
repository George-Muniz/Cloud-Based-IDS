# appengine/main.py
import os
from flask import Flask, request, jsonify
from google.cloud import storage
from google.api_core.exceptions import NotFound

# Import the shared parser packaged inside AppEngine/common
from common.parser import analyze_blob_to_bytes

app = Flask(__name__)

# ---- Config / Env ----
ALLOW_GET_MUTATIONS = os.getenv("ALLOW_GET_MUTATIONS", "false").lower() == "true"
INPUT_BUCKET = os.environ.get("IDS_INPUT_BUCKET")
RESULTS_BUCKET = os.environ.get("IDS_RESULTS_BUCKET")
RESULTS_PREFIX = os.environ.get("IDS_RESULTS_PREFIX", "results/")

# ---- GCS Clients / Buckets ----
storage_client = storage.Client()

def _get_input_bucket():
    if not INPUT_BUCKET:
        raise RuntimeError("IDS_INPUT_BUCKET env var is not set.")
    return storage_client.bucket(INPUT_BUCKET)

def _get_results_bucket():
    if not RESULTS_BUCKET:
        raise RuntimeError("IDS_RESULTS_BUCKET env var is not set.")
    return storage_client.bucket(RESULTS_BUCKET)

# ---- Helpers ----
def _download_bytes(name: str) -> bytes:
    return _get_input_bucket().blob(name).download_as_bytes()

def _write_result(name: str, data: bytes) -> str:
    out_name = f"{RESULTS_PREFIX}{name}.json"
    _get_results_bucket().blob(out_name).upload_from_string(
        data, content_type="application/json"
    )
    return out_name

def _require_post_if_mutating():
    if request.method == "GET" and not ALLOW_GET_MUTATIONS:
        return jsonify({
            "error": "GET disabled for this endpoint in production. Use POST "
                     "or set ALLOW_GET_MUTATIONS=true for dev."
        }), 405
    return None

# ---- Endpoints ----
@app.get("/healthz")
def healthz():
    """Lightweight health check."""
    try:
        # minimal sanity: ensure buckets are configured
        _ = (_get_input_bucket(), _get_results_bucket())
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)}), 500

@app.get("/")
def root():
    try:
        blobs = [b.name for b in _get_input_bucket().list_blobs(max_results=20)]
        msg = "GAE (App Engine) is live. Sample input files: "
        return msg + (", ".join(blobs) if blobs else "(none)")
    except Exception as e:
        return jsonify({"error": "startup/list failed", "detail": str(e)}), 500

@app.get("/list")
def list_blobs():
    try:
        blobs = [b.name for b in _get_input_bucket().list_blobs(max_results=100)]
        return jsonify({"input_blobs": blobs})
    except Exception as e:
        return jsonify({"error": "list failed", "detail": str(e)}), 500

@app.route("/analyze", methods=["GET", "POST"])
def analyze_one():
    guard = _require_post_if_mutating()
    if guard:
        return guard  # 405 if GET not allowed

    blob = request.args.get("blob")
    if not blob:
        return jsonify({"error": "provide ?blob=<name>"}), 400

    try:
        # Validate the blob exists to return a clean 404
        if not _get_input_bucket().blob(blob).exists():
            return jsonify({"error": "blob not found", "blob": blob}), 404

        data = analyze_blob_to_bytes(blob, _download_bytes)
        out_name = _write_result(blob, data)
        return jsonify({"analyzed": blob, "result_blob": out_name})
    except NotFound:
        return jsonify({"error": "blob not found", "blob": blob}), 404
    except Exception as e:
        return jsonify({"error": "analyze failed", "detail": str(e), "blob": blob}), 500

@app.route("/analyze-all", methods=["GET", "POST"])
def analyze_all():
    guard = _require_post_if_mutating()
    if guard:
        return guard  # 405 if GET not allowed

    try:
        processed = []
        for b in _get_input_bucket().list_blobs(max_results=1000):
            data = analyze_blob_to_bytes(b.name, _download_bytes)
            out_name = _write_result(b.name, data)
            processed.append({"blob": b.name, "result_blob": out_name})
        return jsonify({"processed": processed})
    except Exception as e:
        return jsonify({"error": "analyze-all failed", "detail": str(e)}), 500
