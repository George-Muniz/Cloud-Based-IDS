#!/usr/bin/env bash
set -euxo pipefail

apt-get update
apt-get install -y python3-pip python3-venv

mkdir -p /opt/ids/gce /opt/ids/common
# Copy your repo files into /opt/ids (scp, git clone, or gsutil). Adjust as needed.

python3 -m venv /opt/ids/venv
source /opt/ids/venv/bin/activate
pip install --upgrade pip wheel setuptools
pip install flask gunicorn google-cloud-storage

# Persist env
cat >/etc/profile.d/ids-env.sh <<'EOF'
export IDS_INPUT_BUCKET=ids-input-cs-project
export IDS_RESULTS_BUCKET=ids-results-cs-project
export IDS_RESULTS_PREFIX=results/
EOF
source /etc/profile.d/ids-env.sh || true

export PYTHONPATH="/opt/ids:${PYTHONPATH}"
cd /opt/ids/gce
exec /opt/ids/venv/bin/gunicorn -w 1 -k sync -b 0.0.0.0:80 service:app
