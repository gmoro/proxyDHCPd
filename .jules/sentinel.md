## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-08-02 - Partial Match Bypass via re.match
**Vulnerability:** The `ipAddressCheck` method used `re.match` which only matches the start of the string, allowing IP addresses with appended malicious payloads (e.g. `127.0.0.1; rm -rf /`) to pass validation.
**Learning:** Python's `re.match` behavior is unintuitive for full-string validation; this is a common anti-pattern that leads to input validation bypasses.
**Prevention:** Always use `re.fullmatch` for strict string validation when verifying exact formats like IPs, UUIDs, or email addresses.
