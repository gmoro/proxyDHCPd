## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2025-05-04 - Strict IP Address Validation (CWE-185)
**Vulnerability:** Partial regex matching allowed malformed IP addresses and trailing garbage strings (e.g. `192.168.1.1; DROP TABLE users`) to pass IP address validation due to the use of `re.match()`.
**Learning:** `re.match()` only checks if the pattern matches at the beginning of the string. In security contexts like IP validation, this is insufficient and allows bypassing input controls via trailing command injections.
**Prevention:** Always use `re.fullmatch()` when validating IP addresses or strict patterns to ensure the entire string is matched, preventing trailing garbage characters (CWE-185).
