## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2025-02-28 - DoS via Legacy Division in Packet Formatting
**Vulnerability:** In `DhcpPacket.str()`, Python 2 legacy division (`data[iterator]/16`) was used to format the MAC address. In Python 3, this returns a float, causing a `TypeError` which could crash the daemon when attempting to format malformed payloads or log requests.
**Learning:** Legacy syntax that silently worked in Python 2 can become explicit crash vectors (Denial of Service) when executed in Python 3 environments if not audited properly.
**Prevention:** Always use modern string formatting (e.g., `"%02x" % val`) and wrap string representation methods for raw network data in `try...except` blocks to prevent logging errors from crashing the service.
