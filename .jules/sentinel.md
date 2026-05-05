## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - Partial match of IP string regex allowing garbage bypass
**Vulnerability:** In `proxydhcpd/proxyconfig.py`, the `ipAddressCheck` used `re.match` which only checks that the regular expression matches the beginning of the string.
**Learning:** This existed because `re.match` behavior is unintuitive. It allows matching IP addresses with garbage characters following them. `re.fullmatch` must be used to ensure strict validation.
**Prevention:** Always use `re.fullmatch` rather than `re.match` when enforcing validation rules against strings based on regex, unless partial prefix matching is explicitly desired.
