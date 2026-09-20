#!/bin/zsh
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  print -u2 "This installer is for macOS only"
  exit 1
fi
if [[ ! -x /Applications/LibreOffice.app/Contents/MacOS/soffice ]]; then
  print -u2 "LibreOffice is required at /Applications/LibreOffice.app"
  exit 1
fi

SCRIPT_DIR=${0:A:h}
SOURCE_DIR=${SCRIPT_DIR:h}
APP_DIR="$HOME/Applications/wordshield-local"
BASE_DIR="$HOME/Library/Application Support/WordShield"
DATA_DIR="$BASE_DIR/data"
MODEL_DIR="$BASE_DIR/models/privacy-filter"
PRIVACY_MODEL=${PRIVACY_MODEL:-openai/privacy-filter}
if [[ "$PRIVACY_MODEL" == "apararti/privacy-filter-ru" ]]; then
  MODEL_DIR="$BASE_DIR/models/privacy-filter-ru"
elif [[ "$PRIVACY_MODEL" != "openai/privacy-filter" ]]; then
  print -u2 "Unsupported Privacy Filter checkpoint"
  exit 1
fi
LOG_DIR="$BASE_DIR/logs"
VENDOR_DIR="$BASE_DIR/vendor/privacy-filter"
PLIST="$HOME/Library/LaunchAgents/com.wordshield.local.plist"
OPF_COMMIT=f7f00ca7fb869683eb732c010299d901457f19c3
MODEL_REVISION=7ffa9a043d54d1be65afb281eddf0ffbe629385b
PYTHON_BIN=${PYTHON_BIN:-/opt/homebrew/bin/python3.12}
LM_BASE_URL=${LM_BASE_URL:-http://127.0.0.1:1234/v1}
ENABLE_TAILSCALE_SERVE=${ENABLE_TAILSCALE_SERVE:-false}
WORDSHIELD_ALLOWED_USER=${WORDSHIELD_ALLOWED_USER:?Set WORDSHIELD_ALLOWED_USER to the exact Tailscale login allowed to use the service}

if [[ ! -x "$PYTHON_BIN" ]]; then
  print -u2 "Python 3.12 is required at $PYTHON_BIN"
  exit 1
fi

mkdir -p "$APP_DIR" "$DATA_DIR" "$MODEL_DIR" "$LOG_DIR" "$VENDOR_DIR" "$HOME/Library/LaunchAgents"
chmod 700 "$BASE_DIR" "$DATA_DIR" "$MODEL_DIR" "$LOG_DIR"
rsync -a --delete --exclude '.venv' --exclude 'data' "$SOURCE_DIR/" "$APP_DIR/"
"$PYTHON_BIN" -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/python" -m pip install --upgrade pip
"$APP_DIR/.venv/bin/python" -m pip install "$APP_DIR"

if [[ ! -d "$VENDOR_DIR/.git" ]]; then
  git clone https://github.com/openai/privacy-filter.git "$VENDOR_DIR"
fi
git -C "$VENDOR_DIR" fetch --depth 1 origin "$OPF_COMMIT"
git -C "$VENDOR_DIR" checkout --detach "$OPF_COMMIT"
"$APP_DIR/.venv/bin/python" -m pip install "$VENDOR_DIR"
if [[ "$PRIVACY_MODEL" == "openai/privacy-filter" ]]; then
  "$APP_DIR/.venv/bin/python" - <<PY
from huggingface_hub import snapshot_download
snapshot_download(
    repo_id="openai/privacy-filter",
    revision="$MODEL_REVISION",
    local_dir="$MODEL_DIR",
    allow_patterns=["*.json", "*.safetensors", "*.sig"],
)
PY
  EXPECTED_MODEL_SHA256=9c262cbe68a0c8a50590a648ef8341a2b7d3be1fa11dfb79893fe0b03ce57b5c
else
  "$APP_DIR/.venv/bin/python" "$APP_DIR/tools/install_privacy_ru.py" "$MODEL_DIR/original"
  EXPECTED_MODEL_SHA256=dad75869b6130d1cefcaae0efc77eb1885524a7fc2aa47b5a96528d2c0a1904c
fi
ACTUAL_MODEL_SHA256=$(shasum -a 256 "$MODEL_DIR/original/model.safetensors" | awk '{print $1}')
if [[ "$ACTUAL_MODEL_SHA256" != "$EXPECTED_MODEL_SHA256" ]]; then
  print -u2 "Privacy Filter model checksum mismatch"
  exit 1
fi
"$APP_DIR/.venv/bin/python" "$APP_DIR/tools/provision_privacy_tokenizer.py" "$MODEL_DIR/tokenizer-cache"
TIKTOKEN_CACHE_DIR="$MODEL_DIR/tokenizer-cache" HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 "$APP_DIR/.venv/bin/python" - <<PY
from opf import OPF
result = OPF(model="$MODEL_DIR/original", device="cpu", output_mode="typed").redact("Contact alice@example.org")
assert any(span.text == "alice@example.org" for span in result.detected_spans)
PY

SYSTEM_KEYCHAIN=/Library/Keychains/System.keychain
if ! security find-generic-password -s wordshield-local -a master -w "$SYSTEM_KEYCHAIN" >/dev/null 2>&1; then
  print -u2 "WordShield master key is absent from $SYSTEM_KEYCHAIN"
  print -u2 "Run deploy/create-system-key.sh locally once, then rerun this installer."
  exit 1
fi
if [[ -n "${LM_STUDIO_TOKEN:-}" ]]; then
  security add-generic-password -U -s wordshield-lm-studio -a api -w "$LM_STUDIO_TOKEN" "$SYSTEM_KEYCHAIN"
fi

sed -e "s|__APP_DIR__|$APP_DIR|g" \
    -e "s|__DATA_DIR__|$DATA_DIR|g" \
    -e "s|__MODEL_DIR__|$MODEL_DIR|g" \
    -e "s|__LOG_DIR__|$LOG_DIR|g" \
    -e "s|__LM_BASE_URL__|$LM_BASE_URL|g" \
    -e "s|__ALLOWED_USER__|$WORDSHIELD_ALLOWED_USER|g" \
    "$APP_DIR/deploy/com.wordshield.local.plist" > "$PLIST"
chmod 600 "$PLIST"
launchctl bootout "gui/$(id -u)/com.wordshield.local" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
launchctl kickstart -k "gui/$(id -u)/com.wordshield.local"

for attempt in {1..30}; do
  if curl --fail --silent http://127.0.0.1:8844/healthz >/dev/null 2>&1; then
    break
  fi
  if [[ "$attempt" == 30 ]]; then
    print -u2 "WordShield did not become healthy within 30 seconds"
    exit 1
  fi
  sleep 1
done
if [[ "$ENABLE_TAILSCALE_SERVE" == "true" ]]; then
  TAILSCALE_BIN=${TAILSCALE_BIN:-/Applications/Tailscale.app/Contents/MacOS/Tailscale}
  "$TAILSCALE_BIN" serve --bg --yes 8844
  print "Installed and published privately. Check Tailscale Serve status."
else
  print "Installed locally at http://127.0.0.1:8844 (Tailscale Serve not enabled)."
fi
