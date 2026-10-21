"""Local API: uploaded captures are temporary; stored investigations contain metadata only."""
import csv
import io
import json
import multiprocessing as mp
import os
import sqlite3
import tempfile
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

try:
    from .analyzer import AnalysisError, analyze
    from .report import build_pdf
    from .demo import controlled_capture, write_pcap
    from .ml_engine import train_or_load_model
except ImportError:
    from analyzer import AnalysisError, analyze
    from report import build_pdf
    from demo import controlled_capture, write_pcap
    from ml_engine import train_or_load_model

MAX_BYTES = 50 * 1024 * 1024
TIMEOUT = 120

if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    DB_PATH = Path("/tmp/nettrace.sqlite3")
else:
    DB_PATH = Path(os.environ.get("NETTRACE_DB", Path(__file__).parent / "data" / "nettrace.sqlite3"))

app = FastAPI(title="NetTrace API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.execute("CREATE TABLE IF NOT EXISTS investigations (id TEXT PRIMARY KEY, filename TEXT NOT NULL, analyzed_at TEXT NOT NULL, sha256 TEXT NOT NULL, packet_count INTEGER NOT NULL, finding_count INTEGER NOT NULL, data TEXT NOT NULL)")
    return db

def worker(output_path, path, filename, rules):
    try:
        result = {"success": True, "value": analyze(path, filename, rules)}
    except Exception as exc:
        result = {"success": False, "value": str(exc) if isinstance(exc, AnalysisError) else "The capture could not be processed."}
    Path(output_path).write_text(json.dumps(result))

def process_capture(path, filename, rules):
    with tempfile.NamedTemporaryFile(prefix="nettrace-result-", delete=False) as output:
        output_path = output.name
    try:
        try:
            process = mp.get_context("spawn").Process(target=worker, args=(output_path, path, filename, rules))
            process.start()
            process.join(TIMEOUT)
            if process.is_alive():
                process.terminate(); process.join()
                raise HTTPException(408, "Analysis exceeded the 120-second processing limit.")
            result = json.loads(Path(output_path).read_text())
        except (NotImplementedError, OSError, PermissionError):
            # Serverless fallback when multiprocessing spawn is restricted
            try:
                result = {"success": True, "value": analyze(path, filename, rules)}
            except Exception as exc:
                result = {"success": False, "value": str(exc) if isinstance(exc, AnalysisError) else "The capture could not be processed."}
        except (OSError, ValueError):
            raise HTTPException(422, "Capture processing stopped unexpectedly.")
        if not result["success"]:
            raise HTTPException(422, result["value"])
        value = result["value"]
        value["id"] = uuid.uuid4().hex
        with connect() as db:
            db.execute("INSERT INTO investigations VALUES (?, ?, ?, ?, ?, ?, ?)", (value["id"], filename, value["analyzed_at"], value["sha256"], value["summary"]["packets_processed"], len(value["findings"]), json.dumps(value)))
        return value
    finally:
        Path(output_path).unlink(missing_ok=True)

def get_investigation(investigation_id):
    with connect() as db:
        row = db.execute("SELECT data FROM investigations WHERE id=?", (investigation_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Investigation not found.")
    return json.loads(row[0])

@app.get("/api/health")
def health():
    return {"status": "ready"}

@app.get("/api/investigations")
def list_investigations():
    with connect() as db:
        rows = db.execute("SELECT id, filename, analyzed_at, sha256, packet_count, finding_count FROM investigations ORDER BY analyzed_at DESC LIMIT 100").fetchall()
    return [dict(zip(("id", "filename", "analyzed_at", "sha256", "packet_count", "finding_count"), row)) for row in rows]

@app.get("/api/investigations/{investigation_id}")
def detail(investigation_id: str):
    return get_investigation(investigation_id)

@app.post("/api/investigations", status_code=201)
def upload(file: UploadFile = File(...), port_scan: bool = Form(True), syn_heavy: bool = Form(True), repeated: bool = Form(True)):
    filename = Path(file.filename or "").name
    if not filename.lower().endswith((".pcap", ".pcapng")) or len(filename) > 255:
        raise HTTPException(400, "Choose a .pcap or .pcapng file with a valid filename.")
    path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="nettrace-", suffix=Path(filename).suffix, delete=False) as temp:
            path = temp.name
            size = 0
            while chunk := file.file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_BYTES:
                    raise HTTPException(413, "Capture exceeds the 50 MiB upload limit.")
                temp.write(chunk)
        if size == 0:
            raise HTTPException(400, "The selected file is empty.")
        return process_capture(path, filename, {"port_scan": port_scan, "syn_heavy": syn_heavy, "repeated": repeated})
    finally:
        file.file.close()
        if path:
            Path(path).unlink(missing_ok=True)

@app.post("/api/demo", status_code=201)
def demo():
    with tempfile.NamedTemporaryFile(prefix="nettrace-demo-", suffix=".pcap", delete=False) as temp:
        path = temp.name
    try:
        controlled_capture(path)
        return process_capture(path, "controlled-demo.pcap", {"port_scan": True, "syn_heavy": True, "repeated": True})
    finally:
        Path(path).unlink(missing_ok=True)

@app.get("/api/ml/info")
def ml_info():
    """Return trained Random Forest model provenance, benchmark dataset metrics, and feature importances."""
    _, metrics = train_or_load_model()
    return metrics

PRESETS = [
    {
        "id": "01_normal_web",
        "filename": "01_normal_web_traffic.pcap",
        "name": "Clean Web & DNS Baseline",
        "category": "BENIGN",
        "severity": "Minimal",
        "description": "Standard interactive HTTP/HTTPS handshakes with full responses and UDP DNS resolution (port 53).",
        "provenance": "CIC-IDS2017 & UNSW-NB15 Benign Profiles",
        "protocols": ["TCP", "UDP"],
        "expected_findings": 0
    },
    {
        "id": "02_port_scan",
        "filename": "02_port_scan_reconnaissance.pcap",
        "name": "TCP Port Reconnaissance",
        "category": "PORT_SCAN",
        "severity": "High",
        "description": "Host probes 16 distinct well-known services (SSH, Telnet, HTTP, SMB, RDP, MySQL) with minimal replies.",
        "provenance": "CIC-IDS2017 PortScan & UNSW-NB15 Reconnaissance",
        "protocols": ["TCP"],
        "expected_findings": 2
    },
    {
        "id": "03_syn_flood",
        "filename": "03_syn_flood_dos.pcap",
        "name": "SYN Flood DoS Surge",
        "category": "DDOS_SYN_FLOOD",
        "severity": "Critical",
        "description": "Rapid burst of 40 unacknowledged SYN packets targeting web service with 0% observed replies.",
        "provenance": "CIC-IDS2017 DoS LOIC / GoldenEye",
        "protocols": ["TCP"],
        "expected_findings": 1
    },
    {
        "id": "04_ssh_brute",
        "filename": "04_brute_force_repeated_ssh.pcap",
        "name": "SSH Credential Brute-Force",
        "category": "BRUTE_FORCE",
        "severity": "High",
        "description": "12 repeated authentication connection attempts to SSH port 22 spanning over 33 seconds.",
        "provenance": "CIC-IDS2017 SSH-Patator Benchmark",
        "protocols": ["TCP"],
        "expected_findings": 1
    },
    {
        "id": "05_multi_threat",
        "filename": "05_multi_threat_incident.pcap",
        "name": "Multi-Vector Attack Incident",
        "category": "PORT_SCAN / BRUTE_FORCE",
        "severity": "Critical",
        "description": "Full kill-chain: network service sweep followed by persistent SMB brute-force alongside legitimate background clients.",
        "provenance": "Combined Threat Vectors",
        "protocols": ["TCP"],
        "expected_findings": 4
    },
    {
        "id": "06_ipv6_recon",
        "filename": "06_ipv6_network_traffic.pcap",
        "name": "IPv6 Service Discovery",
        "category": "PORT_SCAN (IPv6)",
        "severity": "High",
        "description": "Native IPv6 network probe scanning 9 destination ports across 2001:db8:85a3:: addresses.",
        "provenance": "Modern IPv6 Infrastructure",
        "protocols": ["IPv6 TCP"],
        "expected_findings": 2
    },
    {
        "id": "07_mixed_proto",
        "filename": "07_mixed_protocols_udp_icmp.pcap",
        "name": "Protocol Mix (ICMP/UDP/TCP)",
        "category": "BENIGN",
        "severity": "Minimal",
        "description": "Rich protocol distribution: ICMP Echo ping sweeps, NTP (123), Syslog (514), and TCP.",
        "provenance": "Enterprise Diagnostic Traffic",
        "protocols": ["ICMP", "UDP", "TCP"],
        "expected_findings": 0
    },
    {
        "id": "08_pcapng_recon",
        "filename": "08_enterprise_recon.pcapng",
        "name": "PCAPNG Next-Gen Block Probing",
        "category": "PORT_SCAN",
        "severity": "High",
        "description": "Next-Gen PCAPNG format parsing with Section Header Blocks (SHB) and Interface Description Blocks.",
        "provenance": "PCAPNG Binary Format Verification",
        "protocols": ["TCP"],
        "expected_findings": 1
    },
    {
        "id": "09_vlan_tagged",
        "filename": "09_vlan_tagged_traffic.pcap",
        "name": "802.1Q VLAN Trunking",
        "category": "BENIGN",
        "severity": "Minimal",
        "description": "Enterprise segmented traffic encapsulated with 802.1Q VLAN 100 (DMZ) and VLAN 200 (Core).",
        "provenance": "VLAN Tag Unwrapping Verification",
        "protocols": ["TCP"],
        "expected_findings": 0
    },
    {
        "id": "10_microservices",
        "filename": "10_database_microservices.pcap",
        "name": "Microservices Cluster (DB/Cache)",
        "category": "BENIGN",
        "severity": "Minimal",
        "description": "Complex multi-host architecture: API Gateway, Auth Service, Redis (6379), and PostgreSQL (5432).",
        "provenance": "Cloud Microservice Communication",
        "protocols": ["TCP"],
        "expected_findings": 0
    }
]

@app.get("/api/test-presets")
def list_test_presets():
    """Return catalog of benchmark test captures covering diverse conditions."""
    return PRESETS

@app.post("/api/test-presets/{preset_id}/run", status_code=201)
def run_test_preset(preset_id: str):
    """Run analysis directly on any built-in test preset without requiring manual upload."""
    preset = next((p for p in PRESETS if p["id"] == preset_id), None)
    if not preset:
        raise HTTPException(404, f"Preset '{preset_id}' not found.")
    
    pcap_path = Path(__file__).parent.parent / "sample_pcaps" / preset["filename"]
    if not pcap_path.exists():
        # Auto-regenerate samples if not yet built
        try:
            import subprocess, sys
            gen_script = Path(__file__).parent.parent / "scripts" / "generate_samples.py"
            subprocess.run([sys.executable, str(gen_script)], check=True)
        except Exception:
            raise HTTPException(500, f"Sample capture file '{preset['filename']}' could not be located or generated.")
    
    return process_capture(str(pcap_path), preset["filename"], {"port_scan": True, "syn_heavy": True, "repeated": True})

from pydantic import BaseModel, Field

class CustomConditionRequest(BaseModel):
    source_ip: str = Field("192.168.1.188", description="Source IP address")
    target_ip: str = Field("192.168.1.1", description="Target IP address")
    condition_name: str = Field("Custom Condition Test", description="Descriptive label for test")
    scenario_type: str = Field("custom", description="Preset condition or custom: port_scan, syn_flood, brute_force, c2_beacon, exfiltration, benign, custom")
    packet_count: int = Field(30, ge=4, le=1000)
    ports: list[int] = Field([22, 80, 443], description="Target ports")
    tcp_flags: str = Field("SYN", description="SYN, SYN_ACK, ACK, RST, FIN, XMAS, NULL")
    response_ratio: float = Field(0.0, ge=0.0, le=1.0)
    duration_seconds: float = Field(5.0, ge=0.05, le=120.0)
    protocol: str = Field("TCP", description="TCP, UDP, ICMP")
    packet_size: int = Field(64, ge=54, le=1500)

@app.post("/api/simulate", status_code=201)
def simulate_condition(req: CustomConditionRequest):
    """Dynamic Condition Simulator: Synthesizes arbitrary network conditions and inspects results."""
    import ipaddress, struct, time

    flag_map = {
        "SYN": 0x02,
        "SYN_ACK": 0x12,
        "ACK": 0x10,
        "RST": 0x04,
        "FIN": 0x01,
        "PSH_ACK": 0x18,
        "XMAS": 0x29, # FIN + PSH + URG
        "NULL": 0x00
    }
    chosen_flag = flag_map.get(req.tcp_flags.upper(), 0x02)
    
    # Configure ports based on scenario
    ports = req.ports if req.ports else [80]
    if req.scenario_type == "port_scan" and len(ports) < 8:
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080, 8443]
    elif req.scenario_type == "brute_force":
        ports = [22]
    elif req.scenario_type == "syn_flood":
        ports = [80]
        req.response_ratio = 0.0

    base_time = time.time() - (req.duration_seconds + 5.0)
    records = []
    step = req.duration_seconds / max(1, req.packet_count)

    src = req.source_ip
    dst = req.target_ip

    for i in range(req.packet_count):
        t = base_time + i * step
        dport = ports[i % len(ports)]
        sport = 40000 + (i % 20000)

        if req.protocol.upper() == "UDP":
            payload = b'\x00' * max(0, req.packet_size - 28)
            udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
            ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                             ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
            eth = b'\xaa'*6 + b'\xbb'*6 + struct.pack('!H', 0x0800)
            frame = eth + ip + udp
            records.append((t, frame))
            if req.response_ratio > 0 and (i / req.packet_count) < req.response_ratio:
                # Add reply
                udp_rep = struct.pack('!HHHH', dport, sport, 8 + len(payload), 0) + payload
                ip_rep = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp_rep), 0, 0, 64, 17, 0,
                                     ipaddress.IPv4Address(dst).packed, ipaddress.IPv4Address(src).packed)
                records.append((t + 0.005, eth + ip_rep + udp_rep))
        elif req.protocol.upper() == "ICMP":
            icmp = struct.pack('!BBHHH', 8, 0, 0, 1, i + 1) + b'PingSimulation12'
            ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(icmp), 0, 0, 64, 1, 0,
                             ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
            eth = b'\xaa'*6 + b'\xbb'*6 + struct.pack('!H', 0x0800)
            records.append((t, eth + ip + icmp))
            if req.response_ratio > 0 and (i / req.packet_count) < req.response_ratio:
                icmp_rep = struct.pack('!BBHHH', 0, 0, 0, 1, i + 1) + b'PingSimulation12'
                ip_rep = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(icmp_rep), 0, 0, 64, 1, 0,
                                     ipaddress.IPv4Address(dst).packed, ipaddress.IPv4Address(src).packed)
                records.append((t + 0.005, eth + ip_rep + icmp_rep))
        else: # TCP
            tcp = struct.pack('!HHIIBBHHH', sport, dport, 1000 + i, 0, 5 << 4, chosen_flag, 8192, 0, 0)
            payload_len = max(0, req.packet_size - 40)
            payload = b'\x00' * payload_len
            ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + payload_len, 0, 0, 64, 6, 0,
                             ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
            eth = b'\xaa'*6 + b'\xbb'*6 + struct.pack('!H', 0x0800)
            records.append((t, eth + ip + tcp + payload))
            
            # Response simulation
            if req.response_ratio > 0 and (i / req.packet_count) < req.response_ratio:
                rep_flags = 0x12 if chosen_flag == 0x02 else 0x10 # SYN-ACK or ACK
                rep_tcp = struct.pack('!HHIIBBHHH', dport, sport, 5000 + i, 1001 + i, 5 << 4, rep_flags, 8192, 0, 0)
                ip_rep = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(rep_tcp), 0, 0, 64, 6, 0,
                                     ipaddress.IPv4Address(dst).packed, ipaddress.IPv4Address(src).packed)
                records.append((t + 0.005, eth + ip_rep + rep_tcp))

    records.sort(key=lambda x: x[0])
    
    with tempfile.NamedTemporaryFile(prefix="simulated-condition-", suffix=".pcap", delete=False) as temp:
        path = temp.name
    try:
        write_pcap(path, records)
        safe_name = f"simulated-{req.scenario_type.lower()}-{len(records)}pkts.pcap"
        return process_capture(path, safe_name, {"port_scan": True, "syn_heavy": True, "repeated": True})
    finally:
        Path(path).unlink(missing_ok=True)

@app.get("/api/investigations/{investigation_id}/packets.csv")
def packets_csv(investigation_id: str):
    data = get_investigation(investigation_id)
    output = io.StringIO(newline="")
    columns = ("index", "timestamp", "source", "destination", "source_port", "destination_port", "protocol", "length", "flags")
    writer = csv.DictWriter(output, fieldnames=columns)
    writer.writeheader(); writer.writerows({k: row.get(k) for k in columns} for row in data["packets"])
    return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=nettrace-{investigation_id[:8]}-packets.csv"})

@app.get("/api/investigations/{investigation_id}/report.pdf")
def report_pdf(investigation_id: str):
    data = get_investigation(investigation_id)
    return Response(build_pdf(data), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=nettrace-{investigation_id[:8]}-report.pdf"})


