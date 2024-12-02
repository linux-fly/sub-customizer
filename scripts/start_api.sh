#!/usr/bin/env sh
set -e

pip install -r requirements_api.txt
uvicorn --host 0.0.0.0 --port 58088 sub_customizer.api.app:app --forwarded-allow-ips='*'
