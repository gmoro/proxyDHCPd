## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Injection/Invalid Config via Loose Regex Validation
**Vulnerability:** The `ipAddressCheck` function in `proxydhcpd/proxyconfig.py` used `re.match()` to validate IP addresses. Because `re.match()` only checks if the regex matches at the *beginning* of the string, it accepted malicious inputs with trailing garbage (e.g., `192.168.1.1; rm -rf /`).
**Learning:** This existed because `re.match` is often mistakenly thought to validate the entire string.
**Prevention:** Always use `re.fullmatch()` when strictly validating configuration fields or user inputs to ensure the entire string matches the required pattern without any trailing characters.
