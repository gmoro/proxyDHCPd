## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2025-02-27 - CWE-185 IP Address Validation Bypass via Partial Match
**Vulnerability:** The configuration parser (`proxydhcpd/proxyconfig.py`) used `re.match()` to validate IP addresses. `re.match()` only checks the beginning of the string, allowing maliciously crafted configuration inputs with valid prefixes but invalid suffixes (e.g., `192.168.1.1.evil`) to bypass validation.
**Learning:** This vulnerability existed because the developer did not enforce an explicit anchor at the end of the string. Regular expression methods like `re.match()` are inherently unsafe for strict input validation without explicit anchors `^` and `$`.
**Prevention:** Always use `re.fullmatch()` or explicit string boundary anchors when using regex for input validation to ensure the entire input strictly conforms to the expected format.
