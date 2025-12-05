import argparse
import os
import json

from google.cloud import storage
import requests
#A CLI helper script that calls the batch analyzer locally.
#Used for testing without hitting the API.

def upload_to_gcs(local_path: str, bucket_name: str, object_name: str) -> str:
    # Uploads a local file to GCS and returns the gs:// path.
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(object_name)

    print(f"Uploading {local_path} to gs://{bucket_name}/{object_name} ...")
    blob.upload_from_filename(local_path)
    gs_path = f"gs://{bucket_name}/{object_name}"
    print(f"Uploaded to {gs_path}")
    return gs_path


def call_analyze_batch(base_url: str, gs_path: str):
    # Calls the /analyze_batch endpoint with the given gs_path.
    url = f"{base_url.rstrip('/')}/analyze_batch"
    params = {"gs_path": gs_path}
    print(f"Calling {url} with gs_path={gs_path} ...")

    resp = requests.get(url, params=params, timeout=60)

    if not resp.ok:
        print(f"Request failed: {resp.status_code} {resp.text}")
        return None

    try:
        data = resp.json()
    except Exception:
        print("Failed to parse JSON response:")
        print(resp.text)
        return None

    print("Batch analysis result (summary):")
    print(json.dumps(data, indent=2))
    return data


def main():
    parser = argparse.ArgumentParser(description="Upload CSV to GCS and call /analyze_batch.")
    parser.add_argument(
        "--local_csv",
        default="data/sample_logs.csv",
        help="Path to local CSV file (default: data/sample_logs.csv)",
    )
    parser.add_argument(
        "--bucket",
        required=True,
        help="GCS bucket name (without gs://).",
    )
    parser.add_argument(
        "--object_name",
        default="sample_logs.csv",
        help="Object name to use in GCS (default: sample_logs.csv).",
    )
    parser.add_argument(
        "--base_url",
        required=True,
        help=(
            "Base URL of IDS API. "
            "Examples: http://VM_EXTERNAL_IP:8080 or https://PROJECT_ID.REGION_ID.r.appspot.com"
        ),
    )

    args = parser.parse_args()

    if not os.path.exists(args.local_csv):
        raise FileNotFoundError(f"Local CSV not found: {args.local_csv}")

    # 1) Upload to GCS
    gs_path = upload_to_gcs(args.local_csv, args.bucket, args.object_name)

    # 2) Call /analyze_batch
    call_analyze_batch(args.base_url, gs_path)


if __name__ == "__main__":
    main()
