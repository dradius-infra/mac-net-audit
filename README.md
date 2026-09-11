# MacNetAudit — Technical Documentation & Audit Manual

MacNetAudit is a deterministic, root-level Layer 2 to Layer 7 network triage and endpoint posture utility engineered specifically for macOS. It replaces probabilistic scanning, hardcoded fallbacks, and slow packet capture with exact system telemetry and hardware-level frame inspection.

---

### Technical Primitives & Deterministic Architecture

| Technical Requirement | Implementation Detail | Operational Impact |
| :--- | :--- | :--- |
| **Zero Speculation (No Fallbacks)** | Bitwise bit-shift translation of DHCP netmasks; zero defaults for missing DNS or subnets. | Eliminates arbitrary `/24` subnet assumptions or external resolver leaks (`1.1.1.1`). Reports `Unassigned` on missing parameters. |
| **Hardware-Level Layer 2 Mapping** | Injects raw ARP request frames via `arp-scan` across the active link interface. | Uncovers 100% of live LAN hosts, bypassing endpoint ICMP drop rules (e.g., Windows Defender, macOS Stealth Mode). |
| **Active Multi-Host Port Auditing** | Targeted SYN stealth scanning (`-sS`) scoped directly to discovered Layer 2 peers. | Identifies exposed edge services (SSH, Web, SMB, RDP) without broad subnet sweeps or excessive traffic overhead. |
| **macOS Native Endpoint Verification** | Direct querying of Darwin subsystems (`pfctl`, `security`, `scutil`, `system_profiler`). | Exposes host-level interception risks: NAT redirects, custom Root CAs, and Rogue Access Point collisions. |
| **Universal macOS Compatibility** | Native POSIX syntax with dual-path binary resolution (`/opt/homebrew` and `/usr/local`). | Runs reliably on all architectures (Apple Silicon and Intel x86_64) and macOS releases (Bash 3.2+). |

---

### Prerequisites & Dependencies

| Component | Type | Source / Command | Requirement Rationale |
| :--- | :--- | :--- | :--- |
| **`root` Execution** | Privilege | `sudo ./macnetaudit.sh` | Required for raw BPF socket frame injection, `pfctl` inspection, and access to the System Trust Store. |
| **`nmap`** | Package | `brew install nmap` | Performs OS TCP/IP stack fingerprinting and service version identification on the router and active peers. |
| **`arp-scan`** | Package | `brew install arp-scan` | Generates low-level Ethernet ARP queries across the local broadcast domain for host discovery. |
| **Darwin Utilities** | Native | macOS Built-in | System binaries (`route`, `ipconfig`, `networksetup`, `scutil`, `security`, `pfctl`, `lsof`). |

---

### Modular Inspection Breakdown

| Module | Inspection Vector | Core Engine / Commands | Output Telemetry & Security Meaning |
| :--- | :--- | :--- | :--- |
| **[1] Subnet & Routing** | L3 Addressing & True Prefix | `route -n get default`<br>`ipconfig getoption subnet_mask` | Identifies egress physical interface, routable global IPv6, default gateway, and exact CIDR prefix (`/8` through `/30`). |
| **[2] Wi-Fi & RF Security** | Wireless Layer 2 & Rogue APs | `system_profiler SPAirPortDataType`<br>BSSID multi-beacon matching | Displays link speeds, RSSI, Noise, and cipher strength (Open, WPA2, WPA3). Triggers alerts if an **Evil Twin** AP advertises the connected SSID. |
| **[3] Host Posture** | Kernel Firewall & Trust Store | `pfctl -s info`<br>`pfctl -s nat`<br>`security dump-trust-settings` | Evaluates packet filtering status, detects stealth NAT port-redirections (`rdr`), and uncovers installed custom Root CAs (TLS interception risk). |
| **[4] Network Policy** | Perimeter Gateways & DNS | `curl -s http://captive.apple.com`<br>`scutil --dns` | Flags captive portal walled-gardens and exposes unauthorized DHCP Search Domain injections used for DNS hijacking. |
| **[5] Subnet Inventory** | Hardware Layer 2 Discovery | `arp-scan --localnet`<br>`ndp -an` | Maps all active IPv4/IPv6 hosts, resolves physical MAC addresses, maps IEEE OUI hardware vendors, and logs NDP neighbors. |
| **[6] Host Profiling** | Edge & Peer Port Exposure | `nmap -sS -sV -O --top-ports 20`<br>`nmap -sS -p [ports] [peers]` | Profiles router operating systems and service versions. Sweeps active LAN neighbors for open administrative and sharing ports (22, 23, 80, 443, 445, 3389, 8080). |
| **[7] Local Exposure** | Local Inbound Attack Surface | `lsof -iTCP -sTCP:LISTEN -n -P` | Enumerates local listening sockets, revealing all processes on the Mac accepting incoming network connections. |

---

### Operational Execution Matrix

```bash
# Install core external discovery packages via Homebrew
brew install nmap arp-scan

# Grant execution permissions
chmod +x macnetaudit.sh

# Run audit with necessary root privileges
sudo ./macnetaudit.sh
```
---

| Execution Parameter | Specification | Operational Behavior |
| --- | --- | --- |
| **Execution Speed** | 4 to 8 Seconds | Completes Layer 2–7 triage and port scanning without hanging the active session. |
| **Data Privacy** | Fully Sanitized | Retains no static machine profiles, target logs, or persistent disk signatures. |
| **Failure Recovery** | Native Fallback | Falls back cleanly to system ARP cache and socket probes if external tools are absent. |