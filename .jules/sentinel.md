## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2026-07-02 - Secure File Creation Mask for Daemon
**Vulnerability:** Process daemonization sequence used os.umask(0), creating a risk that subsequent files (logs, pidfiles) would be world-writable.
**Learning:** Daemon decoupling often copies a pattern using umask(0) blindly to reset parent state, but daemons need restrictive default permissions for their own files.
**Prevention:** Always use a secure file creation mask like os.umask(0o022) when daemonizing unless explicitly writing to a shared medium.
