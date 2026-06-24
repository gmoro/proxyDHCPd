## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-06-24 - Insecure Default umask in Daemonization
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` called `os.umask(0)`, effectively removing all file creation masks. This meant that any files or logs created by the daemonized process would be world-writable (e.g., 0666 or 0777), potentially allowing unprivileged local users to tamper with the daemon's log files or other output.
**Learning:** This is a common pitfall when writing daemonization code in Python, where example snippets often reset the umask to 0 so the daemon has full control over the permissions of the files it creates. However, failing to explicitly specify secure permissions in subsequent `open()` calls, or just leaving the umask at 0 for standard operations, creates a security risk.
**Prevention:** Always use a secure umask, such as `os.umask(0o022)`, when writing daemon initialization code unless there is a specific, well-documented reason to allow broader permissions.
