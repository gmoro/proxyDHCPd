## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2026-07-24 - Insecure File Creation Mask (CWE-732)
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` called `os.umask(0)`, which clears the process's file mode creation mask. As a result, any files created subsequently by the daemon (e.g., logs, PID files) would default to being world-writable (permissions like 666 or 777), posing a risk of unauthorized modification.
**Learning:** This is a common pitfall when writing daemonization logic derived from older Unix examples. While detaching from the environment, an explicit *secure* umask must be set, not disabled entirely.
**Prevention:** Always use a secure umask such as `os.umask(0o022)` (or `0o027` depending on required group access) when initializing a daemon to ensure newly created files have safe permissions by default.
