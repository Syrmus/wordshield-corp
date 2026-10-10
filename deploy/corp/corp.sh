#!/bin/sh
# Run as the dedicated unprivileged Linux service account, never with sudo.
set -eu
cd "$(dirname "$0")/../.."
if [ "$(uname -s)" != Linux ] || [ "$(id -u)" = 0 ]; then
    echo 'Use a dedicated non-root account on the Linux server.' >&2
    exit 1
fi
export APP_UID="$(id -u)" APP_GID="$(id -g)"
umask 077
if [ ! -f deploy/corp/.env ]; then
    echo 'Copy deploy/corp/.env.example to deploy/corp/.env and set the HTTPS URL.' >&2
    exit 1
fi
mkdir -p .corp-runtime
gpu_file=
if [ "${1:-}" = --gpu ]; then
    gpu_file=deploy/corp/compose.gpu.yaml
    shift
fi
action="${1:-help}"
compose() {
    if [ -n "$gpu_file" ]; then
        docker compose --env-file deploy/corp/.env -f deploy/corp/compose.yaml -f "$gpu_file" "$@"
    else
        docker compose --env-file deploy/corp/.env -f deploy/corp/compose.yaml "$@"
    fi
}
case "$action" in
    build) compose build app ;;
    init) compose --profile setup run --rm --no-deps init ;;
    models) compose --profile provision run --rm --no-deps provision ;;
    check) compose run --rm --no-deps app python -m wordshield.corp_check ;;
    up)
        test -s .corp-runtime/tls/server.crt && test -s .corp-runtime/tls/server.key || {
            echo 'Install the internal TLS certificate and key first.' >&2; exit 1;
        }
        compose up -d app proxy ;;
    down) compose down ;;
    status) compose ps ;;
    logs) compose logs --tail 80 app ;;
    config) compose config --quiet ;;
    *) echo 'Usage: sh deploy/corp/corp.sh [--gpu] build|init|models|check|up|down|status|logs|config'; exit 1 ;;
esac
