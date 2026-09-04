## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - Partial Match IP Validation Bypass
**Vulnerability:** The `ipAddressCheck` in `proxydhcpd/proxyconfig.py` used `re.match` to validate IP addresses. `re.match` only checks if the pattern matches the beginning of the string, which means input with trailing data (e.g., `192.168.1.1; bad_command`) would bypass validation.
**Learning:** This issue occurs when regular expressions are used for input validation without anchoring them to both the start and end of the string (e.g., using `re.fullmatch` or explicitly adding `^` and `$`).
**Prevention:** Always use `re.fullmatch` instead of `re.match` when enforcing strict format validation in Python to prevent partial matches and trailing payload injection.
