## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Secure umask in daemonization
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` called `os.umask(0)`, which set the file creation mask to 0, resulting in any newly created files or logs (by the daemon or subsequent processes) being world-writable.
**Learning:** This existed due to an outdated practice of resetting umask without explicitly setting a secure default mask during the standard double-fork daemonization process.
**Prevention:** When daemonizing processes, always explicitly use a secure file creation mask like `os.umask(0o022)` rather than `os.umask(0)` to prevent newly created files and logs from being world-writable.
