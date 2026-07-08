## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-06-25 - Insecure Daemonization File Permissions
**Vulnerability:** The daemon initialization logic in `proxydhcpd/cli.py` called `os.umask(0)`, meaning any files or logs created subsequently by the daemon process would be world-writable (permissions like `-rw-rw-rw-` or `-rwxrwxrwx`), potentially allowing local privilege escalation or tampering.
**Learning:** This is a common pitfall when authors copy-paste generic daemonization boilerplates without tailoring security settings to their application's context. A zero umask wipes out all permission restrictions on file creation.
**Prevention:** Always use a secure umask such as `os.umask(0o022)` during daemonization to enforce safe default file permissions (e.g., `-rw-r--r--`).
