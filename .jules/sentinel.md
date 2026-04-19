## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2025-02-28 - Insecure File Permissions via umask(0) During Daemonization
**Vulnerability:** The proxy DHCP daemon reset its file creation mask (`umask`) to `0` when double-forking into the background. This meant any files or logs created by the background process might have world-writable or broadly permissive access by default.
**Learning:** This is a classic daemonization anti-pattern. While detaching from the parent environment, an explicit secure umask (like `0o022`) should be set rather than removing all restrictions.
**Prevention:** Always use a secure `umask` (`0o022` or stricter) in Python daemon logic to ensure default file permissions are properly restricted.

## 2025-02-28 - Partial Validation Bypass in IP Address Configuration Parsing
**Vulnerability:** The configuration parser validated IPv4 addresses using `re.match(pattern, ip_str)`, which only verifies that the string *starts* with a valid IP address. An attacker could append trailing garbage (e.g., `"192.168.1.1/../../etc/passwd"`) that would be accepted by the validation routine but could potentially be misused downstream.
**Learning:** `re.match` is insufficient for strict input validation because it allows trailing characters.
**Prevention:** Use `re.fullmatch` (or anchors `^` and `$`) for strict format validation of configuration variables to prevent trailing garbage injection.
