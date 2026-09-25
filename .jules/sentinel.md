## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-25 - DoS via Unhandled Type/Index Exceptions in Stringification
**Vulnerability:** The `DhcpPacket.str()` method crashed the process when handling malformed packets due to integer division resulting in floats in Python 3 (`data[iterator]/16`) and missing exception handling around string formatting logic.
**Learning:** Legacy Python 2 syntax and absence of generic exception handling in logging functions can lead to Denial of Service when the server processes malformed input and attempts to log it.
**Prevention:** Use standard exception handling (`try...except`) and robust standard formatting (e.g., `"%02x"`) instead of custom loop arithmetic when processing unvalidated binary payload data for debug output.
