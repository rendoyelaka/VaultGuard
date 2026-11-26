#!/usr/bin/env python3
"""Build upload_apk JSON payload with base64-encoded APK written to a file."""
import base64, json, sys

apk_path, chat_id, build_number, filename, out_path = sys.argv[1:]

with open(apk_path, 'rb') as f:
    b64 = base64.b64encode(f.read()).decode()

payload = {
    'chat_id': chat_id,
    'build_number': build_number,
    'filename': filename,
    'apk_b64': b64,
}

with open(out_path, 'w') as f:
    json.dump(payload, f)
