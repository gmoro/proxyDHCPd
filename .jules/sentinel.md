## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - DoS via Missing Bounds Checks on Dynamic Array Parsing
**Vulnerability:** Empty arrays (`[]`) from truncated packets were triggering an `IndexError` when calling functions like `GetHardwareAddress()` or printing packet contents (`str()`), potentially causing the daemon to crash (DoS vector).
**Learning:** Checking the buffer bounds during binary data parsing is insufficient if downstream logic blindly assumes standard length payloads or options exist and attempts to access elements directly (e.g. `array[0]`).
**Prevention:** Defensive coding must extend to consumers of network structures: Always verify arrays returned from network parses are non-empty before accessing specific indices.
