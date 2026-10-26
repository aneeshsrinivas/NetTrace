"""In-process generator for NetTrace benchmark test PCAP/PCAPNG files."""
import ipaddress
import struct
import time
from pathlib import Path

def current_base_time(offset_minutes=15):
    return time.time() - (offset_minutes * 60.0)

def pcap_write(filepath, records, ng=False):
    filepath = Path(filepath)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'wb') as f:
        if ng:
            def block(kind, body):
                length = 12 + len(body)
                f.write(struct.pack('<II', kind, length) + body + struct.pack('<I', length))
            block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
            block(1, struct.pack('<HHI', 1, 0, 65535))
            for timestamp, frame in records:
                value = int(timestamp * 1_000_000)
                pad = b'\0' * ((-len(frame)) % 4)
                block(6, struct.pack('<IIIII', 0, value >> 32, value & 0xffffffff, len(frame), len(frame)) + frame + pad)
        else:
            f.write(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 65535, 1))
            for timestamp, frame in records:
                sec = int(timestamp)
                sub = int((timestamp - sec) * 1_000_000)
                f.write(struct.pack('<IIII', sec, sub, len(frame), len(frame)) + frame)

def build_eth_ipv4_tcp(source, destination, sport, dport, seq=1000, ack=0, flags=0x02, vlan=None):
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

def generate_preset_pcap(filename: str, target_path: Path):
    target_path = Path(target_path)
    t = current_base_time(30)
    pkts = []

    if filename == "01_normal_web_traffic.pcap":
        client = '192.168.1.50'
        dns_server = '1.1.1.1'
        web_server = '142.250.190.46'
        pkts.append((t, build_eth_ipv4_udp(client, dns_server, 54321, 53, b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01')))
        pkts.append((t + 0.015, build_eth_ipv4_udp(dns_server, client, 53, 54321, b'\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x8e\xfa\xbe\x2e')))
        sport = 49152
        pkts.append((t + 0.035, build_eth_ipv4_tcp(client, web_server, sport, 443, seq=100, flags=0x02)))
        pkts.append((t + 0.060, build_eth_ipv4_tcp(web_server, client, 443, sport, seq=5000, ack=101, flags=0x12)))
        pkts.append((t + 0.065, build_eth_ipv4_tcp(client, web_server, sport, 443, seq=101, ack=5001, flags=0x10)))
        pkts.append((t + 0.075, build_eth_ipv4_tcp(client, web_server, sport, 443, seq=101, ack=5001, flags=0x18)))
        sport2 = 49153
        pkts.append((t + 0.125, build_eth_ipv4_tcp(client, web_server, sport2, 80, seq=200, flags=0x02)))
        pkts.append((t + 0.145, build_eth_ipv4_tcp(web_server, client, 80, sport2, seq=7000, ack=201, flags=0x12)))
        pkts.append((t + 0.150, build_eth_ipv4_tcp(client, web_server, sport2, 80, seq=201, ack=7001, flags=0x10)))
        pcap_write(target_path, pkts, ng=False)

    elif filename == "02_port_scan_reconnaissance.pcap":
        attacker = '192.168.1.188'
        target = '192.168.1.1'
        target_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080, 8443]
        for i, port in enumerate(target_ports):
            sport = 50000 + i
            pkts.append((t + i * 0.15, build_eth_ipv4_tcp(attacker, target, sport, port, seq=1000 + i, flags=0x02)))
            if port in (80, 443):
                pkts.append((t + i * 0.15 + 0.01, build_eth_ipv4_tcp(target, attacker, port, sport, seq=0, ack=1000+i+1, flags=0x04)))
        pcap_write(target_path, pkts, ng=False)

    elif filename == "03_syn_flood_dos.pcap":
        attacker = '10.99.1.5'
        target = '10.99.1.100'
        for i in range(40):
            sport = 30000 + i
            pkts.append((t + i * 0.05, build_eth_ipv4_tcp(attacker, target, sport, 80, seq=50000 + i, flags=0x02)))
        pcap_write(target_path, pkts, ng=False)

    elif filename == "04_brute_force_repeated_ssh.pcap":
        attacker = '172.16.8.99'
        target = '172.16.8.10'
        for i in range(12):
            sport = 42000 + i
            conn_time = t + i * 3.0
            pkts.append((conn_time, build_eth_ipv4_tcp(attacker, target, sport, 22, seq=7000 + i * 10, flags=0x02)))
            pkts.append((conn_time + 0.01, build_eth_ipv4_tcp(target, attacker, 22, sport, seq=90000 + i * 10, ack=7001 + i * 10, flags=0x12)))
            pkts.append((conn_time + 0.02, build_eth_ipv4_tcp(attacker, target, sport, 22, seq=7001 + i * 10, ack=90001 + i * 10, flags=0x10)))
            pkts.append((conn_time + 0.10, build_eth_ipv4_tcp(target, attacker, 22, sport, seq=90001 + i * 10, ack=0, flags=0x04)))
        pcap_write(target_path, pkts, ng=False)

    elif filename == "05_multi_threat_incident.pcap":
        bad_actor = '10.0.5.66'
        target_server = '10.0.5.10'
        normal_client = '10.0.5.20'
        for i in range(6):
            pkts.append((t + i * 2.0, build_eth_ipv4_tcp(normal_client, target_server, 61000 + i, 443, seq=100 + i, flags=0x02)))
            pkts.append((t + i * 2.0 + 0.01, build_eth_ipv4_tcp(target_server, normal_client, 443, 61000 + i, seq=800 + i, ack=101 + i, flags=0x12)))
        for i, port in enumerate([21, 22, 80, 135, 139, 445, 1433, 3306, 3389, 8080]):
            pkts.append((t + i * 0.4, build_eth_ipv4_tcp(bad_actor, target_server, 52000 + i, port, seq=2000 + i, flags=0x02)))
        t_smb = t + 5.0
        for i in range(10):
            pkts.append((t_smb + i * 2.5, build_eth_ipv4_tcp(bad_actor, target_server, 53000 + i, 445, seq=3000 + i, flags=0x02)))
        pkts.sort(key=lambda x: x[0])
        pcap_write(target_path, pkts, ng=False)

    elif filename == "06_ipv6_network_traffic.pcap":
        host_a = '2001:db8:85a3::1'
        host_b = '2001:db8:85a3::2'
        pkts.append((t, build_eth_ipv6_tcp(host_a, host_b, 51000, 80, seq=100, flags=0x02)))
        pkts.append((t + 0.02, build_eth_ipv6_tcp(host_b, host_a, 80, 51000, seq=200, ack=101, flags=0x12)))
        pkts.append((t + 0.03, build_eth_ipv6_tcp(host_a, host_b, 51000, 80, seq=101, ack=201, flags=0x10)))
        for i, port in enumerate([22, 53, 80, 443, 8080, 8443, 9000, 9443, 3000]):
            pkts.append((t + 1.0 + i * 0.2, build_eth_ipv6_tcp(host_a, host_b, 52000 + i, port, seq=1000 + i, flags=0x02)))
        pcap_write(target_path, pkts, ng=False)

    elif filename == "07_mixed_protocols_udp_icmp.pcap":
        admin = '192.168.10.5'
        gateway = '192.168.10.1'
        for seq in range(1, 5):
            pkts.append((t + seq * 0.5, build_eth_ipv4_icmp(admin, gateway, icmp_type=8, code=0, seq=seq)))
            pkts.append((t + seq * 0.5 + 0.005, build_eth_ipv4_icmp(gateway, admin, icmp_type=0, code=0, seq=seq)))
        pkts.append((t + 3.0, build_eth_ipv4_udp(admin, gateway, 123, 123, b'\x24\x00\x00\x00' + b'\x00'*44)))
        pkts.append((t + 3.5, build_eth_ipv4_udp(admin, gateway, 48000, 514, b'<14>NetTrace syslog test message')))
        pkts.append((t + 4.0, build_eth_ipv4_tcp(admin, gateway, 55000, 80, seq=500, flags=0x02)))
        pkts.append((t + 4.02, build_eth_ipv4_tcp(gateway, admin, 80, 55000, seq=600, ack=501, flags=0x12)))
        pcap_write(target_path, pkts, ng=False)

    elif filename == "08_enterprise_recon.pcapng":
        scanner = '10.100.1.50'
        corp_srv = '10.100.1.10'
        for i, port in enumerate([22, 80, 111, 443, 2049, 3389, 5900, 8000, 8080]):
            pkts.append((t + i * 0.1, build_eth_ipv4_tcp(scanner, corp_srv, 60000 + i, port, seq=800 + i, flags=0x02)))
        pcap_write(target_path, pkts, ng=True)

    elif filename == "09_vlan_tagged_traffic.pcap":
        dmz_ip = '172.20.10.5'
        core_ip = '172.20.20.1'
        for i in range(5):
            pkts.append((t + i * 0.2, build_eth_ipv4_tcp(dmz_ip, core_ip, 40000 + i, 80, seq=10 + i, flags=0x02, vlan=100)))
            pkts.append((t + i * 0.2 + 0.01, build_eth_ipv4_tcp(core_ip, dmz_ip, 80, 40000 + i, seq=50 + i, ack=11 + i, flags=0x12, vlan=100)))
        for i in range(5):
            pkts.append((t + 2.0 + i * 0.2, build_eth_ipv4_tcp(core_ip, dmz_ip, 45000 + i, 443, seq=20 + i, flags=0x02, vlan=200)))
            pkts.append((t + 2.0 + i * 0.2 + 0.01, build_eth_ipv4_tcp(dmz_ip, core_ip, 443, 45000 + i, seq=70 + i, ack=21 + i, flags=0x12, vlan=200)))
        pcap_write(target_path, pkts, ng=False)

    elif filename == "10_database_microservices.pcap":
        api_gw = '10.8.0.1'
        auth_srv = '10.8.0.2'
        db_pg = '10.8.0.10'
        cache_redis = '10.8.0.11'
        pkts.append((t, build_eth_ipv4_tcp(api_gw, auth_srv, 41001, 8080, seq=100, flags=0x02)))
        pkts.append((t + 0.005, build_eth_ipv4_tcp(auth_srv, api_gw, 8080, 41001, seq=500, ack=101, flags=0x12)))
        pkts.append((t + 0.008, build_eth_ipv4_tcp(api_gw, auth_srv, 41001, 8080, seq=101, ack=501, flags=0x10)))
        pkts.append((t + 0.02, build_eth_ipv4_tcp(auth_srv, cache_redis, 42001, 6379, seq=200, flags=0x02)))
        pkts.append((t + 0.025, build_eth_ipv4_tcp(cache_redis, auth_srv, 6379, 42001, seq=600, ack=201, flags=0x12)))
        pkts.append((t + 0.028, build_eth_ipv4_tcp(auth_srv, cache_redis, 42001, 6379, seq=201, ack=601, flags=0x10)))
        pkts.append((t + 0.04, build_eth_ipv4_tcp(auth_srv, db_pg, 43001, 5432, seq=300, flags=0x02)))
        pkts.append((t + 0.045, build_eth_ipv4_tcp(db_pg, auth_srv, 5432, 43001, seq=700, ack=301, flags=0x12)))
        pkts.append((t + 0.048, build_eth_ipv4_tcp(auth_srv, db_pg, 43001, 5432, seq=301, ack=701, flags=0x10)))
        pcap_write(target_path, pkts, ng=False)
    else:
        raise ValueError(f"Unknown preset filename: {filename}")
    return target_path
