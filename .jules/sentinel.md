## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-06-19 - Insecure file creation mask during daemonization
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` explicitly set the file creation mask to `0` (`os.umask(0)`). This meant any files subsequently created by the daemon would default to world-writable permissions unless specific restrictive permissions were passed upon creation.
**Learning:** This is a legacy practice from older UNIX daemon tutorials that aimed to give the daemon full control, but it violates modern security principles by failing open (defaulting to insecure permissions).
**Prevention:** Always use a restrictive umask like `os.umask(0o022)` (or `0o027` for more strictness) when initializing a daemon to ensure defense-in-depth and prevent accidental creation of world-writable files.
