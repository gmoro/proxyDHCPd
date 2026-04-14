## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2026-04-14 - Partial String Match Bypass in IP Validation
**Vulnerability:** The `ipAddressCheck` function used `re.match` to validate IP addresses, which only validates from the start of the string. This allowed trailing garbage characters (e.g., `192.168.1.1;rm -rf /`) to bypass validation (CWE-185), potentially enabling injection attacks if the IP was used in shell commands or logs.
**Learning:** This existed because `re.match` is commonly misunderstood as matching the whole string, whereas it only matches the prefix.
**Prevention:** Always use `re.fullmatch` for strict string validation when the entire input must match the pattern.
