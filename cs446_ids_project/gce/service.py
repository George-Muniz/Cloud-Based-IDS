import os
from flask import Flask, request, jsonify
from google.cloud import storage

import sys, pathlib
sys.path.append(str(pathlib.Path(__file__).resolve().parents[1] / "common"))
from parser import analyze_blob_to_bytes  # noqa: E402

app = Flask(__name__)

INPUT_BUCKET = os.environ.get("IDS_INPUT_BUCKET", "ids-input-cs-project")
RESULTS_BUCKET = os.environ.get("IDS_RESULTS_BUCKET", "ids-results-cs-project")
RESULTS_PREFIX = os.environ.get("IDS_RESULTS_PREFIX", "results/")

storage_client = storage.Client()
inp_bucket = storage_client.bucket(INPUT_BUCKET)
out_bucket = storage_client.bucket(RESULTS_BUCKET)

def _download_bytes(name: str) -> bytes:
    return inp_bucket.blob(name).download_as_bytes()

def _write_result(name: str, data: bytes) -> str:
    out_name = f"{RESULTS_PREFIX}{name}.json"
    out_blob = out_bucket.blob(out_name)
    out_blob.upload_from_string(data, content_type="application/json")
    return out_name

@app.get("/")
def root():
    blobs = [b.name for b in inp_bucket.list_blobs(max_results=20)]
    return "GCE (VM) is live. Sample input files: " + (", ".join(blobs) or "(none)")

@app.get("/list")
def list_blobs():
    blobs = [b.name for b in inp_bucket.list_blobs(max_results=100)]
    return jsonify({"input_blobs": blobs})

@app.post("/analyze")
def analyze_one():
    blob = request.args.get("blob")
    if not blob:
        return jsonify({"error": "provide ?blob=<name>"}), 400
    data = analyze_blob_to_bytes(blob, _download_bytes)
    out_name = _write_result(blob, data)
    return jsonify({"analyzed": blob, "result_blob": out_name})

@app.post("/analyze-all")
def analyze_all():
    processed = []
    for b in inp_bucket.list_blobs(max_results=1000):
        data = analyze_blob_to_bytes(b.name, _download_bytes)
        out_name = _write_result(b.name, data)
        processed.append({"blob": b.name, "result_blob": out_name})
    return jsonify({"processed": processed})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
