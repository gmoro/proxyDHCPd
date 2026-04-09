## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2026-04-09 - Validation Bypass via Partial Regex Match
**Vulnerability:** The `ipAddressCheck` in `proxydhcpd/proxyconfig.py` used `re.match` which only enforces a match at the *beginning* of the string. This could allow trailing garbage, potentially enabling injection attacks if IPs are passed to unescaped shell commands (e.g., `192.168.1.1; rm -rf /`). This is known as CWE-185.
**Learning:** Python's `re.match` is insufficient for strict input validation when bounding characters like `$` are omitted from the regex pattern.
**Prevention:** Always use `re.fullmatch()` when validating that an entire input string strictly adheres to a regular expression pattern.
