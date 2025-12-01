import os
import csv
import random

RAW_DIR = os.path.join(os.path.dirname(__file__), "csic_raw")
OUT_DIR = os.path.join(os.path.dirname(__file__), "csic_processed")
os.makedirs(OUT_DIR, exist_ok=True)

NORMAL_FILE = os.path.join(RAW_DIR, "normalTrafficTraining.txt")
ANOM_FILE = os.path.join(RAW_DIR, "anomalousTrafficTest.txt")

DEST_LABELED = os.path.join(OUT_DIR, "csic_labeled.csv")
DEST_UNLABELED = os.path.join(OUT_DIR, "csic_logs.csv")

# simple fake IP generator
def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def parse_requests(path, label):
    """
    Very simple parser: CSIC requests are separated by blank lines.
    First line: 'GET /path HTTP/1.1' or 'POST /path HTTP/1.1'
    We treat the rest of the lines as payload/headers joined together.
    """
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    blocks = raw.strip().split("\n\n")
    for block in blocks:
        lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
        if not lines:
            continue

        # first line like: METHOD URL HTTP/1.1
        first = lines[0]
        parts = first.split()
        if len(parts) < 2:
            continue

        method = parts[0]
        url = parts[1]  # includes path + query string

        # split path vs query manually
        if "?" in url:
            path, query = url.split("?", 1)
        else:
            path, query = url, ""

        # treat everything except the first line as "payload-ish"
        rest = "\n".join(lines[1:])
        payload = query
        if rest:
            if payload:
                payload = payload + "&" + rest
            else:
                payload = rest

        src_ip = random_ip()
        dst_ip = "192.168.1.10"

        yield {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "path": path,
            "method": method,
            "payload": payload,
            "label": label,
        }

def main():
    rows = []

    # normal traffic
    if os.path.exists(NORMAL_FILE):
        rows.extend(list(parse_requests(NORMAL_FILE, label=0)))
    else:
        print(f"WARNING: {NORMAL_FILE} not found")

    # anomalous traffic
    if os.path.exists(ANOM_FILE):
        rows.extend(list(parse_requests(ANOM_FILE, label=1)))
    else:
        print(f"WARNING: {ANOM_FILE} not found")

    if not rows:
        print("No rows parsed. Check your csic_raw files.")
        return

    # write labeled CSV (for ML)
    with open(DEST_LABELED, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=["src_ip", "dst_ip", "path", "method", "payload", "label"]
        )
        w.writeheader()
        w.writerows(rows)

    # write unlabeled CSV (for batch analyze)
    with open(DEST_UNLABELED, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=["src_ip", "dst_ip", "path", "method", "payload"]
        )
        w.writeheader()
        for r in rows:
            w.writerow({
                "src_ip": r["src_ip"],
                "dst_ip": r["dst_ip"],
                "path": r["path"],
                "method": r["method"],
                "payload": r["payload"],
            })

    print(f"Wrote labeled CSV:   {DEST_LABELED}")
    print(f"Wrote unlabeled CSV: {DEST_UNLABELED}")
    print(f"Total rows: {len(rows)}")

if __name__ == "__main__":
    main()
