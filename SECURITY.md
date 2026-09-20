# Security policy

WordShield processes sensitive documents. Do not include real documents,
findings, alias mappings, database files, encrypted blobs, keys, tokens, host
addresses, usernames, or production logs in issues or pull requests.

Report vulnerabilities privately through GitHub's **Security → Report a
vulnerability** flow. Do not open a public issue containing exploit details or
document data.

The application has no cloud fallback. Production deployments should bind to
loopback, verify the exact Tailscale identity, keep model runtimes offline, and
store the master key in the macOS System Keychain.
