## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - Partial IP Match Vulnerability
**Vulnerability:** In `proxydhcpd/proxyconfig.py`, `re.match` was used for IP validation which only matches from the beginning of the string, allowing partial matches with trailing garbage characters like `192.168.1.1 garbage`.
**Learning:** Using `re.match` for exact pattern validation is risky as it doesn't enforce the end of the string boundary unless explicitly anchored with `$`.
**Prevention:** Always use `re.fullmatch` for exact string matching to prevent trailing payload injection or partial matches.
## 2024-05-24 - Insecure Daemon Umask
**Vulnerability:** In `proxydhcpd/cli.py`, during daemonization, `os.umask(0)` was called, creating a scenario where newly created files (like process logs) by the daemon could be world-writable by default.
**Learning:** Calling `os.umask(0)` explicitly removes all permission restrictions for newly created files. This should be avoided in daemons unless explicitly required, and even then, specific files should be chmodded.
**Prevention:** Use a secure default like `os.umask(0o022)` which ensures files are not world-writable by default.
