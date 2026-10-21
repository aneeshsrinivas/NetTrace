"""Script to generate comprehensive test PCAP and PCAPNG files for NetTrace."""
import os
import struct
import ipaddress
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "sample_pcaps"
OUTPUT_DIR.mkdir(exist_ok=True)

def current_base_time(offset_minutes=15):
    """Dynamic timestamp aligned to the current live date and time."""
    return time.time() - (offset_minutes * 60.0)


def pcap_write(filepath, records, ng=False):
    """Write packets to PCAP or PCAPNG format."""
    with open(filepath, 'wb') as f:
        if ng:
            def block(kind, body):
                length = 12 + len(body)
                f.write(struct.pack('<II', kind, length) + body + struct.pack('<I', length))
            # Section Header Block (SHB)
            block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
            # Interface Description Block (IDB): linktype 1 (Ethernet), snaplen 65535
            block(1, struct.pack('<HHI', 1, 0, 65535))
            # Enhanced Packet Blocks (EPB)
            for timestamp, frame in records:
                value = int(timestamp * 1_000_000)
                pad = b'\0' * ((-len(frame)) % 4)
                block(6, struct.pack('<IIIII', 0, value >> 32, value & 0xffffffff, len(frame), len(frame)) + frame + pad)
        else:
            # PCAP Global Header: magic microsecond little-endian
            f.write(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 65535, 1))
            for timestamp, frame in records:
                sec = int(timestamp)
                sub = int((timestamp - sec) * 1_000_000)
                f.write(struct.pack('<IIII', sec, sub, len(frame), len(frame)) + frame)

def build_eth_ipv4_tcp(source, destination, sport, dport, seq=1000, ack=0, flags=0x02, vlan=None):
    """Flags: 0x02=SYN, 0x12=SYN-ACK, 0x10=ACK, 0x04=RST, 0x18=PSH-ACK"""
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 8192, 0, 0)
    ip_len = 20 + len(tcp)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, ip_len, 0, 0, 64, 6, 0,
                     ipaddress.IPv4Address(source).packed,
                     ipaddress.IPv4Address(destination).packed)
    if vlan is not None:
        eth = b'\xaa'*6 + b'\xbb'*6 + struct.pack('!HH', 0x8100, vlan) + struct.pack('!H', 0x0800)
    else:
        eth = b'\xaa'*6 + b'\xbb'*6 + struct.pack('!H', 0x0800)
    return eth + ip + tcp

def build_eth_ipv4_udp(source, destination, sport, dport, payload=b'\x00'*16):
    udp_len = 8 + len(payload)
    udp = struct.pack('!HHHH', sport, dport, udp_len, 0) + payload
    ip_len = 20 + len(udp)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, ip_len, 0, 0, 64, 17, 0,
                     ipaddress.IPv4Address(source).packed,
                     ipaddress.IPv4Address(destination).packed)
    eth = b'\xaa'*6 + b'\xbb'*6 + struct.pack('!H', 0x0800)
    return eth + ip + udp

def build_eth_ipv4_icmp(source, destination, icmp_type=8, code=0, ident=1, seq=1):
    icmp = struct.pack('!BBHHH', icmp_type, code, 0, ident, seq) + b'PingPayload1234'
    ip_len = 20 + len(icmp)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, ip_len, 0, 0, 64, 1, 0,
                     ipaddress.IPv4Address(source).packed,
                     ipaddress.IPv4Address(destination).packed)
    eth = b'\xaa'*6 + b'\xbb'*6 + struct.pack('!H', 0x0800)
    return eth + ip + icmp

def build_eth_ipv6_tcp(source, destination, sport, dport, seq=1000, ack=0, flags=0x02):
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 8192, 0, 0)
    # IPv6 header: 40 bytes. version(6), traffic class, flow label, payload length, next header (6=TCP), hop limit (64)
    ipv6 = struct.pack('!IHBB16s16s', 0x60000000, len(tcp), 6, 64,
                       ipaddress.IPv6Address(source).packed,
                       ipaddress.IPv6Address(destination).packed)
    eth = b'\xaa'*6 + b'\xbb'*6 + struct.pack('!H', 0x86dd)
    return eth + ipv6 + tcp

def build_eth_ipv6_udp(source, destination, sport, dport, payload=b'\x00'*16):
    udp_len = 8 + len(payload)
    udp = struct.pack('!HHHH', sport, dport, udp_len, 0) + payload
    ipv6 = struct.pack('!IHBB16s16s', 0x60000000, len(udp), 17, 64,
                       ipaddress.IPv6Address(source).packed,
                       ipaddress.IPv6Address(destination).packed)
    eth = b'\xaa'*6 + b'\xbb'*6 + struct.pack('!H', 0x86dd)
    return eth + ipv6 + udp

# ----------------- SCENARIOS -----------------

def gen_01_normal_web_traffic():
    """Clean HTTP/HTTPS sessions with full handshakes and DNS. No security findings."""
    t = current_base_time(45)
    pkts = []
    client = '192.168.1.50'
    dns_server = '1.1.1.1'
    web_server = '142.250.190.46'

    # 1. DNS Query & Response
    pkts.append((t, build_eth_ipv4_udp(client, dns_server, 54321, 53, b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01')))
    t += 0.015
    pkts.append((t, build_eth_ipv4_udp(dns_server, client, 53, 54321, b'\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x8e\xfa\xbe\x2e')))

    # 2. HTTPS Connection (Port 443): 3-Way Handshake
    t += 0.020
    sport = 49152
    pkts.append((t, build_eth_ipv4_tcp(client, web_server, sport, 443, seq=100, flags=0x02))) # SYN
    t += 0.025
    pkts.append((t, build_eth_ipv4_tcp(web_server, client, 443, sport, seq=5000, ack=101, flags=0x12))) # SYN-ACK
    t += 0.005
    pkts.append((t, build_eth_ipv4_tcp(client, web_server, sport, 443, seq=101, ack=5001, flags=0x10))) # ACK
    t += 0.010
    pkts.append((t, build_eth_ipv4_tcp(client, web_server, sport, 443, seq=101, ack=5001, flags=0x18))) # PSH-ACK (TLS Client Hello)

    # 3. HTTP Connection (Port 80)
    t += 0.050
    sport2 = 49153
    pkts.append((t, build_eth_ipv4_tcp(client, web_server, sport2, 80, seq=200, flags=0x02))) # SYN
    t += 0.020
    pkts.append((t, build_eth_ipv4_tcp(web_server, client, 80, sport2, seq=7000, ack=201, flags=0x12))) # SYN-ACK
    t += 0.005
    pkts.append((t, build_eth_ipv4_tcp(client, web_server, sport2, 80, seq=201, ack=7001, flags=0x10))) # ACK

    pcap_write(OUTPUT_DIR / "01_normal_web_traffic.pcap", pkts)

def gen_02_port_scan_recon():
    """Attacker probes 16 distinct ports on a target router/server. Triggers Port Scanning & SYN-heavy."""
    t = current_base_time(40)
    pkts = []
    attacker = '192.168.1.188'
    target = '192.168.1.1'
    target_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080, 8443]

    for i, port in enumerate(target_ports):
        sport = 50000 + i
        # Attacker sends SYN
        pkts.append((t + i * 0.15, build_eth_ipv4_tcp(attacker, target, sport, port, seq=1000 + i, flags=0x02)))
        # Only port 80 and 443 respond with RST, all other ports filtered/closed
        if port in (80, 443):
            pkts.append((t + i * 0.15 + 0.01, build_eth_ipv4_tcp(target, attacker, port, sport, seq=0, ack=1000+i+1, flags=0x04)))

    pcap_write(OUTPUT_DIR / "02_port_scan_reconnaissance.pcap", pkts)

def gen_03_syn_flood_dos():
    """High-volume SYN flood targeting web server port 80 with unacknowledged SYNs."""
    t = current_base_time(35)
    pkts = []
    attacker = '10.99.1.5'
    target = '10.99.1.100'

    for i in range(40):
        sport = 30000 + i
        pkts.append((t + i * 0.05, build_eth_ipv4_tcp(attacker, target, sport, 80, seq=50000 + i, flags=0x02)))

    pcap_write(OUTPUT_DIR / "03_syn_flood_dos.pcap", pkts)

def gen_04_ssh_bruteforce_repeated():
    """Repeated login/connection attempts to SSH port 22 spanning 30 seconds. Triggers Repeated Connections."""
    t = current_base_time(30)
    pkts = []
    attacker = '172.16.8.99'
    target = '172.16.8.10'

    # 12 repeated connection attempts over 36 seconds (every 3 seconds)
    for i in range(12):
        sport = 42000 + i
        conn_time = t + i * 3.0
        # Initial SYN
        pkts.append((conn_time, build_eth_ipv4_tcp(attacker, target, sport, 22, seq=7000 + i * 10, flags=0x02)))
        # Server replies SYN-ACK
        pkts.append((conn_time + 0.01, build_eth_ipv4_tcp(target, attacker, 22, sport, seq=90000 + i * 10, ack=7001 + i * 10, flags=0x12)))
        # Attacker ACK
        pkts.append((conn_time + 0.02, build_eth_ipv4_tcp(attacker, target, sport, 22, seq=7001 + i * 10, ack=90001 + i * 10, flags=0x10)))
        # Reset / close after bad credential
        pkts.append((conn_time + 0.10, build_eth_ipv4_tcp(target, attacker, 22, sport, seq=90001 + i * 10, ack=0, flags=0x04)))

    pcap_write(OUTPUT_DIR / "04_brute_force_repeated_ssh.pcap", pkts)

def gen_05_multi_threat_incident():
    """Complex scenario: host scanning network ports, then launching persistent brute force attacks."""
    t = current_base_time(25)
    pkts = []
    bad_actor = '10.0.5.66'
    target_server = '10.0.5.10'
    normal_client = '10.0.5.20'

    # Background normal traffic
    for i in range(6):
        pkts.append((t + i * 2.0, build_eth_ipv4_tcp(normal_client, target_server, 61000 + i, 443, seq=100 + i, flags=0x02)))
        pkts.append((t + i * 2.0 + 0.01, build_eth_ipv4_tcp(target_server, normal_client, 443, 61000 + i, seq=800 + i, ack=101 + i, flags=0x12)))

    # Threat 1: Port scan across 10 ports
    for i, port in enumerate([21, 22, 80, 135, 139, 445, 1433, 3306, 3389, 8080]):
        pkts.append((t + i * 0.4, build_eth_ipv4_tcp(bad_actor, target_server, 52000 + i, port, seq=2000 + i, flags=0x02)))

    # Threat 2: Repeated connection attempts to port 445 (SMB) across 25 seconds
    t_smb = t + 5.0
    for i in range(10):
        pkts.append((t_smb + i * 2.5, build_eth_ipv4_tcp(bad_actor, target_server, 53000 + i, 445, seq=3000 + i, flags=0x02)))

    # Sort packets strictly by timestamp
    pkts.sort(key=lambda x: x[0])
    pcap_write(OUTPUT_DIR / "05_multi_threat_incident.pcap", pkts)

def gen_06_ipv6_traffic_and_scan():
    """Modern IPv6 traffic: DNS, HTTP, and an IPv6 reconnaissance scan."""
    t = current_base_time(20)
    pkts = []
    host_a = '2001:db8:85a3::1'
    host_b = '2001:db8:85a3::2'

    # Normal IPv6 web session
    pkts.append((t, build_eth_ipv6_tcp(host_a, host_b, 51000, 80, seq=100, flags=0x02)))
    pkts.append((t + 0.02, build_eth_ipv6_tcp(host_b, host_a, 80, 51000, seq=200, ack=101, flags=0x12)))
    pkts.append((t + 0.03, build_eth_ipv6_tcp(host_a, host_b, 51000, 80, seq=101, ack=201, flags=0x10)))

    # IPv6 Port scan
    for i, port in enumerate([22, 53, 80, 443, 8080, 8443, 9000, 9443, 3000]):
        pkts.append((t + 1.0 + i * 0.2, build_eth_ipv6_tcp(host_a, host_b, 52000 + i, port, seq=1000 + i, flags=0x02)))

    pcap_write(OUTPUT_DIR / "06_ipv6_network_traffic.pcap", pkts)

def gen_07_mixed_protocols():
    """Protocol diversity: TCP, UDP (DNS, NTP, Syslog), and ICMP Echo ping sweeps."""
    t = current_base_time(15)
    pkts = []
    admin = '192.168.10.5'
    gateway = '192.168.10.1'

    # ICMP ping sequence
    for seq in range(1, 5):
        pkts.append((t + seq * 0.5, build_eth_ipv4_icmp(admin, gateway, icmp_type=8, code=0, seq=seq)))
        pkts.append((t + seq * 0.5 + 0.005, build_eth_ipv4_icmp(gateway, admin, icmp_type=0, code=0, seq=seq)))

    # UDP NTP (port 123) and Syslog (port 514)
    pkts.append((t + 3.0, build_eth_ipv4_udp(admin, gateway, 123, 123, b'\x24\x00\x00\x00' + b'\x00'*44)))
    pkts.append((t + 3.5, build_eth_ipv4_udp(admin, gateway, 48000, 514, b'<14>NetTrace syslog test message')))

    # TCP Web traffic
    pkts.append((t + 4.0, build_eth_ipv4_tcp(admin, gateway, 55000, 80, seq=500, flags=0x02)))
    pkts.append((t + 4.02, build_eth_ipv4_tcp(gateway, admin, 80, 55000, seq=600, ack=501, flags=0x12)))

    pcap_write(OUTPUT_DIR / "07_mixed_protocols_udp_icmp.pcap", pkts)

def gen_08_pcapng_enterprise_recon():
    """Next-Gen PCAPNG format test file containing an enterprise scan."""
    t = current_base_time(10)
    pkts = []
    scanner = '10.100.1.50'
    corp_srv = '10.100.1.10'

    for i, port in enumerate([22, 80, 111, 443, 2049, 3389, 5900, 8000, 8080]):
        pkts.append((t + i * 0.1, build_eth_ipv4_tcp(scanner, corp_srv, 60000 + i, port, seq=800 + i, flags=0x02)))

    pcap_write(OUTPUT_DIR / "08_enterprise_recon.pcapng", pkts, ng=True)

def gen_09_vlan_tagged_traffic():
    """802.1Q VLAN tagged frames (VLAN 100 DMZ and VLAN 200 Core)."""
    t = current_base_time(5)
    pkts = []
    dmz_ip = '172.20.10.5'
    core_ip = '172.20.20.1'

    # VLAN 100 packets
    for i in range(5):
        pkts.append((t + i * 0.2, build_eth_ipv4_tcp(dmz_ip, core_ip, 40000 + i, 80, seq=10 + i, flags=0x02, vlan=100)))
        pkts.append((t + i * 0.2 + 0.01, build_eth_ipv4_tcp(core_ip, dmz_ip, 80, 40000 + i, seq=50 + i, ack=11 + i, flags=0x12, vlan=100)))

    # VLAN 200 packets
    for i in range(5):
        pkts.append((t + 2.0 + i * 0.2, build_eth_ipv4_tcp(core_ip, dmz_ip, 45000 + i, 443, seq=20 + i, flags=0x02, vlan=200)))
        pkts.append((t + 2.0 + i * 0.2 + 0.01, build_eth_ipv4_tcp(dmz_ip, core_ip, 443, 45000 + i, seq=70 + i, ack=21 + i, flags=0x12, vlan=200)))

    pcap_write(OUTPUT_DIR / "09_vlan_tagged_traffic.pcap", pkts)

def gen_10_database_microservices():
    """Clean multi-host microservices communicating with PostgreSQL, Redis, and API Gateway."""
    t = current_base_time(1)
    pkts = []
    api_gw = '10.8.0.1'
    auth_srv = '10.8.0.2'
    db_pg = '10.8.0.10'
    cache_redis = '10.8.0.11'

    # API GW -> Auth Service (port 8080)
    pkts.append((t, build_eth_ipv4_tcp(api_gw, auth_srv, 41001, 8080, seq=100, flags=0x02)))
    pkts.append((t + 0.005, build_eth_ipv4_tcp(auth_srv, api_gw, 8080, 41001, seq=500, ack=101, flags=0x12)))
    pkts.append((t + 0.008, build_eth_ipv4_tcp(api_gw, auth_srv, 41001, 8080, seq=101, ack=501, flags=0x10)))

    # Auth Service -> Redis Cache (port 6379)
    pkts.append((t + 0.02, build_eth_ipv4_tcp(auth_srv, cache_redis, 42001, 6379, seq=200, flags=0x02)))
    pkts.append((t + 0.025, build_eth_ipv4_tcp(cache_redis, auth_srv, 6379, 42001, seq=600, ack=201, flags=0x12)))
    pkts.append((t + 0.028, build_eth_ipv4_tcp(auth_srv, cache_redis, 42001, 6379, seq=201, ack=601, flags=0x10)))

    # Auth Service -> Postgres DB (port 5432)
    pkts.append((t + 0.04, build_eth_ipv4_tcp(auth_srv, db_pg, 43001, 5432, seq=300, flags=0x02)))
    pkts.append((t + 0.045, build_eth_ipv4_tcp(db_pg, auth_srv, 5432, 43001, seq=700, ack=301, flags=0x12)))
    pkts.append((t + 0.048, build_eth_ipv4_tcp(auth_srv, db_pg, 43001, 5432, seq=301, ack=701, flags=0x10)))

    pcap_write(OUTPUT_DIR / "10_database_microservices.pcap", pkts)

def main():
    print(f"Generating test PCAP files into: {OUTPUT_DIR}")
    generators = [
        ("01_normal_web_traffic.pcap", gen_01_normal_web_traffic),
        ("02_port_scan_reconnaissance.pcap", gen_02_port_scan_recon),
        ("03_syn_flood_dos.pcap", gen_03_syn_flood_dos),
        ("04_brute_force_repeated_ssh.pcap", gen_04_ssh_bruteforce_repeated),
        ("05_multi_threat_incident.pcap", gen_05_multi_threat_incident),
        ("06_ipv6_network_traffic.pcap", gen_06_ipv6_traffic_and_scan),
        ("07_mixed_protocols_udp_icmp.pcap", gen_07_mixed_protocols),
        ("08_enterprise_recon.pcapng", gen_08_pcapng_enterprise_recon),
        ("09_vlan_tagged_traffic.pcap", gen_09_vlan_tagged_traffic),
        ("10_database_microservices.pcap", gen_10_database_microservices),
    ]

    for name, func in generators:
        func()
        print(f" -> Generated: {name}")

    print("\nAll sample PCAPs generated successfully!")

if __name__ == '__main__':
    main()
