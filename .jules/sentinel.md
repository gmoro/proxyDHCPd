## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-06-11 - Type-mismatch bug on DHCP Options
**Bug:** In `SetOption` of `proxydhcpd/dhcplib/dhcp_basic_packet.py`, fixed-length DHCP options (like `ipv4`) could silently accept longer payloads due to a list-vs-integer comparison (`specs==length`), which falsely evaluates to False without raising an error, falling through to less strict minimum length checks.
**Learning:** Python allows direct comparison between lists and integers, evaluating to False rather than throwing a type error. This masks logic errors when verifying data lengths in network protocol parsers.
**Prevention:** Always compare integer fields directly (e.g., `specs[0]==length`) and explicitly require variable-length constraints to only run when fixed length is set to 0.
