## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-26 - Incomplete regex matching for IP validation (CWE-185)
**Vulnerability:** The `ipAddressCheck` function used `re.match` to validate IP addresses against a regex pattern. Because `re.match` only checks for a match at the beginning of the string, it could incorrectly validate input strings that start with a valid IP address but also contain arbitrary trailing garbage (e.g., `192.168.1.1; rm -rf /`).
**Learning:** This is a classic python regex pitfall where `re.match` allows a partial match, whereas input validation requires a full match to ensure the entire input strictly conforms to the expected format.
**Prevention:** Always use `re.fullmatch` (or wrap the pattern in `^` and `$`) when using regular expressions for strict security-critical input validation.
