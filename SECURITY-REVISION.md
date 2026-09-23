# Security revision, 2026-09-23

## Implemented

- Explicit OOXML part allowlist; reject unknown, duplicate and encrypted parts.
- Remove document thumbnails as well as visible images. Old exported documents
  remain restorable; thumbnails are stripped before parsing them.
- Preserve legacy source offsets while giving detectors explicit line breaks.
  Crossing findings are mapped into separate ranges, never silently dropped.
- Independently prove expected text and break positions after patching. Compare
  XML outside authorised value slots, in addition to the existing Word checks.
- Share one compiled replacement plan between review, decisions and export.
- Require digits for automatically accepted English document numbers. A generic
  word from an organization name is no longer proof of a leak.
- Parse at most one uploaded file in memory; cap the entire multipart stream,
  fields, file size, and upload duration. Serialize upload admission.
- Admit at most four analysis jobs and execute one at a time. Resume persisted
  jobs on restart, preserving existing review decisions.
- Use RAM-backed workspaces for conversion and render, including restoration.
  On startup, clean verified WordShield RAM volumes whose owner process died.
- Add an application password alongside Tailscale identity. Store a scrypt hash;
  issue signed Secure/HttpOnly/SameSite=Strict cookies lasting 30 days. Rate-limit
  password attempts. Production startup requires an authentication configuration.
- Exclude the document store from Time Machine during deployment.
- Keep Qwen in a separate optional adapter; the production service does not
  instantiate it or retrieve its access token.

## Administrative isolation (operator step)

`tools/isolate_service.py --agent <existing-launch-agent.plist> --check` performs
read-only preflight. The same command without `--check`, run with sudo, prepares
a hidden `_wordshield` service account and root-owned runtime, verifies imports,
Keychain access, RAM workspace creation and network denial, then moves the one
existing data store and starts a LaunchDaemon. The old agent is disabled only
after the new health check passes. Sessions and encryption keys are not copied.

The service policy denies access to user home directories and network egress.
Runtime code and model files are root-owned. Data files belong to `_wordshield`
and are private. Telegram applications remain under their existing account.

`sudo python3 tools/isolate_service.py --rollback` stops the new daemon, moves
the same store back, restores its original ownership and starts the old agent.
The rollback refuses to overwrite either location when both stores exist.
No accounts or runtime directories are deleted by rollback.

Administrator access is required for creating the account and installing the
LaunchDaemon. A successful non-admin preflight is not proof of a completed OS
migration. After the administrative command, rerun the HTTPS synthetic workflow,
verify the service UID and confirm denial of user-home access and network egress.

## Verification

Installed revision: 190 automated tests passed, including legacy DOC tests.
The bilingual three-page fixture produced 113 automatic replacements and zero
pending findings. DOCX and MD export and restoration passed both in an isolated
store and through the deployed HTTPS service. An older synthetic export restored
113 occurrences successfully. Real RAM-render and crash-cleanup checks passed
under the deployed network sandbox. The store is excluded from Time Machine.
The administrative account migration is prepared but not yet executed.

Regression tests cover hidden ZIP entries, line-break spans, neutral contract
wording, false organization-fragment alarms, unrelated text/formatting changes,
multipart memory handling/limits/timeouts, header forgery, session-cookie expiry,
queue limits, stable plans, and non-destructive rollback. Existing DOC import,
DOCX export, Markdown export and restoration tests are retained.

`tools/verify_security_release.py` uses an isolated synthetic store with the
installed local models. It checks DOCX/MD exports, original text and line breaks
after restoration, public references, and image-preview removal.
`tools/verify_live_security.py` repeats authentication and the synthetic workflow
through HTTPS and can restore an export from an older synthetic session.

## Boundaries

No detector guarantees detection of all sensitive information. The export proof
guarantees execution of the chosen replacements, not completeness of detection.
RAM workspaces do not promise protection from privileged memory inspection or
swap; host FileVault and OS access control remain relevant. Backup exclusion does
not erase pre-existing backups. Browser authentication alone does not isolate
processes running under the service's own OS account: finish the administrative
migration to separate WordShield from the bot account.
