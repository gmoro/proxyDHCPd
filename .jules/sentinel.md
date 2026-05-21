## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-21 - Partial Regex Match on Config Validation
**Vulnerability:** The `ipAddressCheck` in `parse_config` used `re.match` to validate IP addresses. `re.match` only checks for a match at the beginning of the string, allowing IP addresses with trailing garbage (like `192.168.1.1; malicous_command` or similar unexpected input) to bypass validation and be parsed successfully (CWE-185).
**Learning:** Python's `re.match` is insufficient for strict input validation because it accepts partial matches at the string start. Security validation must explicitly enforce start and end boundaries (`^` and `$`) or use `re.fullmatch` to ensure the entire string matches the expected format.
**Prevention:** Always use `re.fullmatch` (or wrap expressions with `^...$`) when performing security or input validation against regex patterns to prevent trailing garbage from bypassing validation.
