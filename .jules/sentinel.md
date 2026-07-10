## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Partial Regular Expression Match Vulnerability (CWE-185)
**Vulnerability:** In `proxydhcpd/proxyconfig.py`, the `ipAddressCheck` function used `re.match` to validate IP addresses. `re.match` only checks for a match at the beginning of the string, which meant that strings like "192.168.1.1 trailing_garbage" would be incorrectly validated as correct IP addresses.
**Learning:** `re.match` is prone to CWE-185 when validating full inputs because it doesn't assert the end of the string.
**Prevention:** Always use `re.fullmatch` (or `re.match` with `^` and `$`) for input validation to ensure the entire input matches the pattern and to prevent partial matches.
