## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - Insecure Default Umask in Daemonization
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` called `os.umask(0)`, resetting the file creation mask to completely open, which causes any files (like logs) created subsequently by the daemon to be world-writable.
**Learning:** Legacy scripts sometimes set `os.umask(0)` as part of boilerplate double-fork logic without realizing it disables all default permissions restrictions.
**Prevention:** Always use a secure file creation mask, such as `os.umask(0o022)`, when writing daemon initialization routines to ensure newly created files remain secure by default.
