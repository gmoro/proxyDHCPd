## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Insecure Daemon File Creation Umask
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` called `os.umask(0)`, resetting the process's file creation mask. This would cause any subsequently created files (such as log files or PID files) by the daemon to be created world-writable, allowing unauthorized local users to modify them.
**Learning:** This existed because `os.umask(0)` is a common, outdated boilerplate copy-pasted in older Python daemonization tutorials to ensure the daemon doesn't inherit a restrictive umask from the parent shell. However, it fails to set a new, secure default.
**Prevention:** When daemonizing processes, always use a secure, restrictive mask like `os.umask(0o022)` rather than `os.umask(0)` to ensure newly created files and logs are not world-writable.
