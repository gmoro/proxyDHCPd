# ProxyDHCPd: The Zero-Configuration Network Boot Router

[![Python 3](https://img.shields.io/badge/Python-3-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-GPLv2-green.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)

**ProxyDHCPd** is a lightweight, strictly Python 3-native ProxyDHCP server built using an embedded fork of `pydhcplib`. It is designed to solve one of the most persistent headaches in systems administration: configuring complex PXE boot environments across multiple architectures without touching your organization's primary DHCP infrastructure or writing brittle regex rules in DNSmasq/ISC-DHCP.

Its "killer feature" is **out-of-the-box native iPXE chainloading** via strict RFC 4578 architecture whitelisting, preventing the legendary PXE infinite boot loop natively through a single `config.ini` file.

## Features

- **No Primary DHCP Modification**: Runs alongside your existing network assigning IPs, only responding to PXE boot requests on Port 4011/67.
- **Strict RFC 4578 Architecture Whitelisting (Option 93)**: Dynamically routes payloads based on the hardware requesting them (Legacy BIOS vs. EFI IA32 vs. EFI x86_64).
- **Native iPXE Chainloading (Option 77)**: Detects when the client is booting from iPXE and securely chainloads them to your final script (e.g., `boot.ipxe`), breaking the infinite loop automatically.
- **Single Source of Truth Configuration**: No complex regex required. Set your parameters in `[ipxe]` inside the `config.ini` file, and the daemon handles the routing.
- **Graceful Unsupported Drops**: Avoids DHCP server crashes by safely dropping unsupported ROM architecture (e.g., ARM64) payloads before encoding.

---

## The iPXE "Infinite Loop" Solved

When implementing iPXE, a common problem occurs: The initial hardware ROM requests a PXE payload and receives `undionly.kpxe`. The machine boots into iPXE, which immediately broadcasts *another* DHCP request. If the server isn't intelligent enough to distinguish between the hardware ROM and the software ROM, it sends `undionly.kpxe` again, creating an infinite loop.

ProxyDHCPd inspects the **User Class (Option 77)** to detect the `iPXE` signature, cleanly rerouting the secondary broadcast to your HTTP endpoint without you needing to write convoluted DHCP expressions.

```mermaid
sequenceDiagram
    participant PC as Hardware Client
    participant DHCP as Primary DHCP Server
    participant Proxy as ProxyDHCPd
    participant TFTP as TFTP Server
    participant HTTP as HTTP Server

    Note over PC, HTTP: Stage 1: Hardware ROM Boot Request
    PC->>DHCP: DHCP DISCOVER (Broadcast)
    DHCP-->>PC: DHCPOFFER (IP Address: 192.168.1.10)
    PC->>Proxy: DHCP DISCOVER (Port 4011 / Option 93)
    Note over Proxy: Parses Option 93:<br/>[0, 0] = Legacy BIOS
    Proxy-->>PC: DHCPOFFER (TFTP IP + undionly.kpxe)
    PC->>TFTP: Request undionly.kpxe
    TFTP-->>PC: Load undionly.kpxe into RAM
    Note over PC, HTTP: Stage 2: iPXE Ecosystem Chainload
    PC->>DHCP: DHCP DISCOVER (Broadcast)
    DHCP-->>PC: DHCPOFFER (IP Address: 192.168.1.10)
    PC->>Proxy: DHCP DISCOVER (Port 4011 / Option 77="iPXE")
    Note over Proxy: Detects Option 77.<br/>Redirects to chainload_url
    Proxy-->>PC: DHCPOFFER (TFTP IP + boot.ipxe)
    PC->>HTTP: Fetch http://server/boot.ipxe
    HTTP-->>PC: Execute Scripts & Provision OS
```

---

## Installation & Requirements

ProxyDHCPd relies entirely on native Python 3 execution and includes its own internal fork of `pydhcplib`, meaning there are **zero external network dependencies** outside of the Python 3 standard library.

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-repo/proxydhcpd.git
   cd proxydhcpd
   ```

2. **System Requirements:**
   - Linux Operating System
   - Python 3.6+
   - Root privileges (to bind to restricted port 67)

---

## Configuration (`proxy.ini`)

ProxyDHCP is driven entirely by an INI configuration file. You do not need to learn complex templating to route your boot payloads.

```ini
[proxy]
listen_address=192.168.188.20
tftpd=192.168.188.20
# Specify the legacy fallback if [ipxe] isn't enabled
filename=undionly.kpxe
vendor_specific_information="proxyDHCPd"

### The Engine Room: Native iPXE Chainloading ###
[ipxe]
# Set to 'true' to dynamically break the infinite loop
enabled=true

# Stage 1: The Initial ROM Payloads (Option 93 Routing)
# If the machine is Legacy BIOS [0, 0], serve this file
legacy_bootstrap=undionly.kpxe
# If the machine is UEFI x64 [0, 7] or [0, 9], serve this file
efi_bootstrap=ipxe.efi

# Stage 2: The iPXE Chainload (Option 77 Routing)
# If the machine broadcast says "I am currently running iPXE",
# serve the final execution script.
chainload_url=boot.ipxe
```

---

## Development & Testing

We strictly enforce isolated environments for local development. **Do not run global `pip` installs.** 

To set up your sandbox and run the test suite, run the following commands sequentially:

```bash
# 1. Create a dedicated virtual environment
python3 -m venv venv

# 2. Activate the virtual environment
source venv/bin/activate

# 3. Install the testing and development dependencies
pip install -r requirements-dev.txt

# 4. Run the Pytest suite with missing lines and HTML report generated
pytest --cov=proxydhcpd.dhcpd --cov-report=term-missing --cov-report=html tests/

# 5. Exit the sandbox when done
deactivate
```

---

## Production Deployment (Systemd)

To run ProxyDHCPd securely in production, configure it as a standard Systemd daemon. 

Create the file `/etc/systemd/system/proxydhcpd.service`:

```ini
[Unit]
Description=Python 3 ProxyDHCP Daemon (iPXE Router)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Ensure the working directory matches your clone or PIP installation
WorkingDirectory=/opt/proxydhcpd/
# Run the daemonized client directly, passing the config file
ExecStart=/usr/bin/python3 -m proxydhcpd.cli -c /etc/proxyDHCPd/proxy.ini
# Fast failures logic
Restart=on-failure
RestartSec=5
# Hardened permissions
User=root
Group=root
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
```

Reload the daemon and enable it to start on boot:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now proxydhcpd
sudo systemctl status proxydhcpd
```
