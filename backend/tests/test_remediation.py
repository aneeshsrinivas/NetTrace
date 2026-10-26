import io
import struct
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import main

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'DB_PATH', tmp_path / 'remediation_test.sqlite3')
    return TestClient(main.app)

def make_one_syn_pcap() -> bytes:
    """Generate a valid, deterministic 94-byte single-packet PCAP fixture."""
    hdr = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00'
    eth = b'\xaa'*6 + b'\xbb'*6 + b'\x08\x00'
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 0, 0, 64, 6, 0, b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02')
    tcp = struct.pack('!HHIIBBHHH', 12345, 80, 100, 0, 5 << 4, 0x02, 8192, 0, 0)
    pkt = eth + ip + tcp
    rec = struct.pack('<IIII', 1700000000, 0, len(pkt), len(pkt))
    data = hdr + rec + pkt
    assert len(data) == 94
    return data

def test_b02_one_packet_pcap_processing(client):
    """B02 Regression: 94-byte 1-packet capture must process promptly without timing out."""
    pcap_bytes = make_one_syn_pcap()
    response = client.post(
        '/api/investigations',
        files={'file': ('one-syn.pcap', pcap_bytes, 'application/octet-stream')}
    )
    assert response.status_code == 201, response.text
    data = response.json()
    assert data['summary']['packets_processed'] == 1
    assert data['summary']['hosts'] == 2
    assert data['summary']['protocols'] == {'TCP': 1}
    assert len(data['packets']) == 1
    assert data['packets'][0]['source'] == '10.0.0.1'
    assert data['packets'][0]['destination'] == '10.0.0.2'
    assert data['packets'][0]['destination_port'] == 80

def test_b01_all_ten_presets_execute_successfully(client):
    """B01 Regression: All 10 public benchmark presets must execute and return valid results."""
    presets_resp = client.get('/api/test-presets')
    assert presets_resp.status_code == 200
    presets = presets_resp.json()
    assert len(presets) == 10

    for preset in presets:
        preset_id = preset['id']
        run_resp = client.post(f'/api/test-presets/{preset_id}/run')
        assert run_resp.status_code == 201, f"Preset {preset_id} failed: {run_resp.text}"
        data = run_resp.json()
        assert 'id' in data
        assert data['filename'] == preset['filename']
        assert data['summary']['packets_processed'] > 0
        assert 'findings' in data
        assert 'ml_analysis' in data
        assert data['sha256']

def test_b04_custom_condition_ip_validation(client):
    """B04 Regression: Invalid IP addresses must be rejected with 422 and specific error messages."""
    # 1. Invalid source IP string
    bad_payload = {
        "source_ip": "not-an-ip",
        "target_ip": "192.168.1.1",
        "condition_name": "Test",
        "scenario_type": "custom",
        "packet_count": 10,
        "ports": [80],
        "tcp_flags": "SYN",
        "response_ratio": 0.0,
        "duration_seconds": 2.0,
        "protocol": "TCP",
        "packet_size": 64
    }
    resp = client.post('/api/simulate', json=bad_payload)
    assert resp.status_code == 422
    assert "not a valid IPv4 or IPv6 address" in resp.text

    # 2. Invalid target IP string
    bad_payload["source_ip"] = "192.168.1.100"
    bad_payload["target_ip"] = "999.999.999.999"
    resp = client.post('/api/simulate', json=bad_payload)
    assert resp.status_code == 422
    assert "not a valid IPv4 or IPv6 address" in resp.text

    # 3. Invalid port list
    bad_payload["target_ip"] = "192.168.1.1"
    bad_payload["ports"] = [80, 70000]
    resp = client.post('/api/simulate', json=bad_payload)
    assert resp.status_code == 422
    assert "out of valid range" in resp.text

def test_valid_custom_simulation_workflows(client):
    """Test custom condition simulations across protocols and scenario types."""
    # 1. TCP custom simulation
    payload_tcp = {
        "source_ip": "192.168.1.50",
        "target_ip": "192.168.1.1",
        "condition_name": "Clean Web Sim",
        "scenario_type": "benign",
        "packet_count": 16,
        "ports": [80, 443],
        "tcp_flags": "SYN",
        "response_ratio": 1.0,
        "duration_seconds": 2.0,
        "protocol": "TCP",
        "packet_size": 64
    }
    resp = client.post('/api/simulate', json=payload_tcp)
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data['summary']['packets_processed'] >= 16

    # 2. UDP simulation
    payload_udp = {
        "source_ip": "10.0.0.5",
        "target_ip": "10.0.0.1",
        "condition_name": "UDP Sim",
        "scenario_type": "custom",
        "packet_count": 10,
        "ports": [53, 123],
        "tcp_flags": "SYN",
        "response_ratio": 0.5,
        "duration_seconds": 1.0,
        "protocol": "UDP",
        "packet_size": 64
    }
    resp = client.post('/api/simulate', json=payload_udp)
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data['summary']['protocols'].get('UDP', 0) > 0

    # 3. ICMP simulation
    payload_icmp = {
        "source_ip": "10.0.0.5",
        "target_ip": "10.0.0.1",
        "condition_name": "ICMP Sim",
        "scenario_type": "custom",
        "packet_count": 8,
        "ports": [0],
        "tcp_flags": "SYN",
        "response_ratio": 0.5,
        "duration_seconds": 1.0,
        "protocol": "ICMP",
        "packet_size": 64
    }
    resp = client.post('/api/simulate', json=payload_icmp)
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data['summary']['protocols'].get('ICMP', 0) > 0
