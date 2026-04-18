## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2026-04-18 - CWE-185 Partial Match Vulnerability in IP Validation
**Vulnerability:** The `ipAddressCheck` method in `proxydhcpd/proxyconfig.py` used `re.match` which only matches the beginning of the string. This allowed trailing garbage characters (e.g., `192.168.1.1 garbage`) to pass the IP validation check.
**Learning:** This existed because `re.match` is often mistakenly thought to validate the whole string when it actually only requires the pattern to be at the start of the string. The regex lacked explicit end-of-string anchors (`$`).
**Prevention:** When validating security-critical input structures like IP addresses, always use `re.fullmatch` to ensure the entire input exactly conforms to the expected pattern.
