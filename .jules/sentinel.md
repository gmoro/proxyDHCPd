## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-20 - Fix IP Validation using fullmatch
**Vulnerability:** Input validation flaw in `proxyconfig.py` allowed IP address strings with trailing garbage (e.g., `192.168.1.1; bad_command`) to pass validation due to the use of `re.match()`, which only matches the start of a string.
**Learning:** `re.match()` in Python does not enforce strict input length boundaries, creating a risk of CWE-185 (Incorrect Regular Expression) where malicious payloads appended to valid input are accepted.
**Prevention:** Always use `re.fullmatch()` or explicitly anchor regex patterns with `^` and `$` to ensure the entire input string is validated.
