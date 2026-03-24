## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2025-02-14 - DoS via Unhandled Out-Of-Bounds Exception in GetHardwareAddress
**Vulnerability:** The `GetHardwareAddress` function in `proxydhcpd/dhcplib/dhcp_packet.py` reads the "hlen" option and accesses the 0-th index without checking if the list is empty. `GetOption` returns an empty list (`[]`) if the option is missing or malformed, meaning `self.GetOption("hlen")[0]` can raise an `IndexError`. This unhandled exception causes the `ProxyDHCPd` daemon to crash, which is a Denial of Service (DoS) vulnerability.
**Learning:** This existed because the parsing logic assumed well-formed payloads and didn't validate the structure or presence of expected fields like `hlen`.
**Prevention:** Always validate that dynamically parsed lists and arrays are non-empty before accessing their elements, especially when dealing with untrusted network payloads. Provide safe fallback defaults.
