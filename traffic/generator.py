import argparse
import json
import random
import time
import requests

def load_samples(path="traffic/sample_requests.json"):
    with open(path) as f:
        return json.load(f)

def send_traffic(base_url, samples, rps=2, duration=30):
    end_time = time.time() + duration
    total = 0
    alerts = 0
    errors = 0

    while time.time() < end_time:
        event = random.choice(samples)

        try:
            resp = requests.post(f"{base_url}/analyze", json=event, timeout=5)
            if resp.ok:
                data = resp.json().get("detection", {})
                if data.get("is_intrusion"):
                    alerts += 1
            else:
                errors += 1
        except Exception as e:
            print("Error:", e)
            errors += 1

        total += 1
        time.sleep(1.0 / rps)

    return {"total": total, "alerts": alerts, "errors": errors}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Base URL like http://localhost:8000")
    parser.add_argument("--rps", type=int, default=2)
    parser.add_argument("--duration", type=int, default=30)
    args = parser.parse_args()

    samples = load_samples()
    stats = send_traffic(args.url, samples, args.rps, args.duration)
    print("Traffic stats:", stats)
