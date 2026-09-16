## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-25 - DoS via TypeError in MAC Address Parsing
**Vulnerability:** Legacy Python 2 division (`/`) returns a float in Python 3, which causes a `TypeError` when used as an array index for `hexsym` during MAC address formatting, potentially crashing the daemon on malformed payloads.
**Learning:** Implicit type changes across Python versions (like float division) can introduce fatal crash vectors in binary parsing logic that previously worked in Python 2.
**Prevention:** Use string formatting (`%02x`) or floor division (`//`) to ensure type safety in array indices and binary-to-string operations.
