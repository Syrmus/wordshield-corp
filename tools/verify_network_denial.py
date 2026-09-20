"""Run inside the proposed application sandbox. Uses no document content."""
import json
import socket

checks = {}
for host in ("1.1.1.1", "8.8.8.8", "100.64.0.1", "127.0.0.1"):
    try:
        with socket.socket() as sock:
            sock.settimeout(2)
            sock.connect((host, 443))
    except PermissionError:
        checks[host] = "OS-denied"
    except OSError as exc:
        raise RuntimeError("Network test inconclusive: " + type(exc).__name__) from None
    else:
        raise RuntimeError("Network isolation failed")
print(json.dumps({"passed": True, "checks": checks}))
