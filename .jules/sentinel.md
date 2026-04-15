## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - Partial Matching with re.match (CWE-185)
 **Vulnerability:** `re.match` was used for IP address validation, allowing partial matches where valid IPs appended with garbage data (e.g., `192.168.1.1; echo hi`) would pass validation.
 **Learning:** `re.match` only checks for a match at the beginning of the string. In security contexts like IP validation, this is insufficient and can lead to command injection or configuration bypasses if the unsanitized suffix is processed later.
 **Prevention:** Always use `re.fullmatch` for strict string validation when the entire input must adhere to the regular expression pattern.
