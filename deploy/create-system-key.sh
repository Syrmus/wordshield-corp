#!/bin/zsh
set -euo pipefail

SYSTEM_KEYCHAIN=/Library/Keychains/System.keychain

if security find-generic-password -s wordshield-local -a master -w "$SYSTEM_KEYCHAIN" >/dev/null 2>&1; then
  print "WordShield master key already exists in System.keychain."
  exit 0
fi

sudo -v
MASTER_KEY=$(openssl rand -base64 32)
sudo security add-generic-password \
  -s wordshield-local \
  -a master \
  -D "WordShield encryption master key" \
  -T /usr/bin/security \
  -w "$MASTER_KEY" \
  "$SYSTEM_KEYCHAIN"
unset MASTER_KEY

if ! security find-generic-password -s wordshield-local -a master -w "$SYSTEM_KEYCHAIN" >/dev/null 2>&1; then
  print -u2 "The key was created but is not readable by the WordShield account."
  exit 1
fi

print "WordShield master key created in System.keychain and verified."
