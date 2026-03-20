## 2025-02-23 - Denial of Service via Malformed DHCP Packets
**Vulnerability:** A missing bounds check in the packet decoding loop (`proxydhcpd/dhcplib/dhcp_basic_packet.py`) causes an `IndexError` when parsing options that lack a subsequent length byte, resulting in the server crashing.
**Learning:** Network packet parsing loops iterating over raw byte arrays must explicitly verify that reading subsequent offsets (like option lengths or values) does not exceed the packet boundaries. The assumption that DHCP options are properly formatted can be maliciously abused.
**Prevention:** Always bound check iterator advancements and array accesses against the calculated packet size (`end_iterator`) before indexing into the array.
