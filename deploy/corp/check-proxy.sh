#!/bin/sh
# Synthetic TLS only. No production secrets, network service, or host ports.
set -eu
cd "$(dirname "$0")/../.."
task_tls_dir=$(mktemp -d)
cleanup() {
    rm -f "$task_tls_dir/server.key" "$task_tls_dir/server.crt"
    rmdir "$task_tls_dir"
}
trap cleanup EXIT HUP INT TERM
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$task_tls_dir/server.key" \
    -out "$task_tls_dir/server.crt" -days 1 -subj /CN=wordshield.example.invalid >/dev/null 2>&1
docker run --rm --network none --user "$(id -u):$(id -g)" \
    --read-only --cap-drop ALL --security-opt no-new-privileges \
    --tmpfs /tmp:size=64m,mode=1777 --add-host app:127.0.0.1 \
    -v "$task_tls_dir:/tls:ro" -v "$PWD/deploy/corp/nginx.conf:/etc/nginx/nginx.conf:ro" \
    nginx:1.28-alpine nginx -t
