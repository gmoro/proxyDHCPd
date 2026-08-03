## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-08-02 - World-Writable Files via Insecure Daemon umask
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` explicitly called `os.umask(0)`. This completely clears the file creation mode mask, meaning any files subsequently created by the daemon process (such as logs or PID files) are created world-writable by default unless strictly protected.
**Learning:** This vulnerability existed due to copy-pasting an outdated, classic Unix double-fork daemonization pattern without considering the security implications of file creation permissions.
**Prevention:** Always use a secure umask, such as `os.umask(0o022)`, when writing daemonization logic or initializing background processes.
