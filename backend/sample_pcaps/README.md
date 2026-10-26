# NetTrace Sample PCAPs & Testing Suite

This folder contains synthetic and controlled PCAP/PCAPNG test captures designed for exploring and evaluating the NetTrace investigation engine.

Each file is tailored to simulate specific network behaviors, protocol variations, or threat scenarios.

---

### Capture Catalog

| File Name | Protocol(s) | Primary Scenario | Expected NetTrace Findings |
| :--- | :--- | :--- | :--- |
| **`01_normal_web_traffic.pcap`** | TCP, UDP | Clean web browsing session (DNS query/response on port 53, completed HTTP/HTTPS handshakes with full responses). | **0 findings** (Clean baseline) |
| **`02_port_scan_reconnaissance.pcap`** | TCP | Host `192.168.1.188` actively probes 16 distinct well-known ports on `192.168.1.1` (SSH, HTTP, SMB, RDP, MySQL, etc.). | **F-001** (Port scanning), **F-002** (SYN-heavy) |
| **`03_syn_flood_dos.pcap`** | TCP | Attacker `10.99.1.5` floods web server `10.99.1.100:80` with 40 rapid unacknowledged SYN packets. | **F-002** (SYN-heavy activity; 0% response ratio) |
| **`04_brute_force_repeated_ssh.pcap`** | TCP | Repeated credential brute-force connection attempts targeting SSH `172.16.8.10:22` spanning >30 seconds. | **F-003** (Repeated connections to one service) |
| **`05_multi_threat_incident.pcap`** | TCP | Combined threat scenario: network reconnaissance probing 10 ports, followed by persistent brute-force on SMB port 445, with legitimate client traffic in background. | **Multiple findings** (Port scanning, SYN-heavy, Repeated connections) |
| **`06_ipv6_network_traffic.pcap`** | IPv6 / TCP | Native IPv6 traffic between `2001:db8:85a3::1` and `2001:db8:85a3::2`, including normal HTTP and an IPv6 port scan. | **F-001** (Port scanning on IPv6), **F-002** (SYN-heavy) |
| **`07_mixed_protocols_udp_icmp.pcap`** | ICMP, UDP, TCP | Multi-protocol traffic inspection: ICMP Echo ping sweeps, UDP NTP (port 123), UDP Syslog (port 514), and TCP. | **0 findings** (Shows protocol distribution in explorer) |
| **`08_enterprise_recon.pcapng`** | PCAPNG / TCP | Next-Generation PCAP format (`.pcapng` with Section Header and Interface Description Blocks) containing enterprise network probes. | **F-001** (Port scanning over PCAPNG) |
| **`09_vlan_tagged_traffic.pcap`** | 802.1Q VLAN / TCP | Enterprise trunk link with 802.1Q VLAN encapsulation (VLAN 100 DMZ and VLAN 200 Core). Tests frame unwrapping. | **0 findings** (Verifies tagged frame decoding) |
| **`10_database_microservices.pcap`** | TCP | Internal microservice infrastructure: API Gateway (`10.8.0.1`), Auth Service (`10.8.0.2`), PostgreSQL DB (`10.8.0.10`), Redis (`10.8.0.11`). | **0 findings** (Clean multi-host topology) |

---

### How to Test in NetTrace

1. Open the NetTrace web UI at **[http://127.0.0.1:5173](http://127.0.0.1:5173)**.
2. Click **Start investigation** or click **Browse capture file**.
3. Select any `.pcap` or `.pcapng` file from this folder (`sample_pcaps/`).
4. Click **Run analysis**.
5. Inspect the generated:
   - **Summary metrics**: Packet count, host count, duration, protocol breakdowns.
   - **Findings**: Triggered heuristics with evidence packet links.
   - **Traffic Explorer**: Filterable packet table.
   - **Hosts & Connections**: Source/destination communication matrices.
   - **Timeline**: Packet rate over time buckets.
   - **Export**: Generate PDF incident reports or CSV packet logs.
