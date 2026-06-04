## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-06-04 - Insecure Default Permissions (CWE-732) via umask(0)
**Vulnerability:** The daemonization process in `proxydhcpd/cli.py` called `os.umask(0)`, which sets the file creation mask to allow read, write, and execute permissions for everyone (owner, group, and others) on newly created files by the daemon.
**Learning:** This occurred because zeroing out the umask is a common but dangerous boilerplate pattern in older daemonization tutorials to ensure the daemon doesn't inherit restrictive umasks, without considering the security implications of world-writable files.
**Prevention:** Always use a secure umask such as `os.umask(0o022)` when daemonizing processes to ensure that newly created files are writable only by the owner, while remaining readable by the group and others (if necessary).
