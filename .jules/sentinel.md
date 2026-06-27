## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-06-27 - Incomplete Regex Matching for Input Validation
**Vulnerability:** The `ipAddressCheck` method used `re.match` which only verifies the beginning of a string against the pattern. This allowed inputs with trailing garbage (like "192.168.1.1 garbage") to pass validation, potentially causing issues downstream if the input is parsed or logged without further verification.
**Learning:** `re.match` is insecure for full input validation, particularly when validating fields that need to conform strictly to a format (like IP addresses). It only checks for a match at the beginning of the string (CWE-185).
**Prevention:** Always use `re.fullmatch` (or pad the regex with `^` and `$`) for strict validation, ensuring that the entire string matches the specified pattern.
