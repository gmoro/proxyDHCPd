## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - World-Writable Files via Insecure Daemon umask
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` called `os.umask(0)`, which clears the process umask. As a result, any files created by the daemon (like logs or pid files) could be world-writable (CWE-732), allowing local privilege escalation or tampering.
**Learning:** This likely occurred because standard double-fork daemonization tutorials sometimes instruct to reset the umask to `0` to prevent inheriting restrictive permissions from the parent, forgetting to set it to a secure baseline like `022`.
**Prevention:** Always use a secure file creation mask like `os.umask(0o022)` when daemonizing processes to ensure that newly created files are minimally writable by others (e.g., `-rw-r--r--`).
