"""Automated API endpoint test suite for NetTrace covering presets, simulations, uploads, and data integrity."""
import json
import os
import struct
import unittest
from fastapi.testclient import TestClient

from backend import main

def make_one_syn_pcap() -> bytes:
    hdr = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00'
    eth = b'\xaa'*6 + b'\xbb'*6 + b'\x08\x00'
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 0, 0, 64, 6, 0, b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02')
    tcp = struct.pack('!HHIIBBHHH', 12345, 80, 100, 0, 5 << 4, 0x02, 8192, 0, 0)
    pkt = eth + ip + tcp
    rec = struct.pack('<IIII', 1700000000, 0, len(pkt), len(pkt))
    data = hdr + rec + pkt
    assert len(data) == 94
    return data

class TestApiEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def test_health_check(self):
        resp = self.client.get('/api/health')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "ready"})

    def test_ml_info_metrics(self):
        resp = self.client.get('/api/ml/info')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("accuracy", data)
        self.assertIn("f1_score", data)
        self.assertGreaterEqual(data["accuracy"], 0.8)
        self.assertLessEqual(data["accuracy"], 1.0)

    def test_list_presets(self):
        resp = self.client.get('/api/test-presets')
        self.assertEqual(resp.status_code, 200)
        presets = resp.json()
        self.assertEqual(len(presets), 10)
        ids = [p['id'] for p in presets]
        self.assertEqual(len(ids), len(set(ids)))

    def test_run_benchmark_presets_clean_and_attacks(self):
        # 1. Clean Web
        resp = self.client.post('/api/test-presets/01_normal_web/run')
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertIn('BENIGN', data['summary']['overall_severity'])

        # 2. Recon Port Scan
        resp = self.client.post('/api/test-presets/02_port_scan/run')
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertIn('Port scanning', [f['rule'] for f in data['findings']])

        # 3. SYN Flood DoS
        resp = self.client.post('/api/test-presets/03_syn_flood/run')
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertIn('SYN-heavy activity', [f['rule'] for f in data['findings']])

    def test_upload_single_packet_pcap(self):
        pcap_data = make_one_syn_pcap()
        resp = self.client.post(
            '/api/investigations',
            files={'file': ('single.pcap', pcap_data, 'application/octet-stream')}
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data['summary']['packets_processed'], 1)
        self.assertEqual(len(data['packets']), 1)

    def test_custom_simulation_tcp_and_udp(self):
        # TCP
        payload_tcp = {
            "source_ip": "10.0.1.10",
            "target_ip": "10.0.1.1",
            "condition_name": "TCP Test",
            "scenario_type": "custom",
            "packet_count": 12,
            "ports": [80],
            "tcp_flags": "SYN",
            "response_ratio": 0.0,
            "duration_seconds": 1.0,
            "protocol": "TCP",
            "packet_size": 64
        }
        resp = self.client.post('/api/simulate', json=payload_tcp)
        self.assertEqual(resp.status_code, 201)

        # UDP
        payload_udp = {
            "source_ip": "10.0.1.10",
            "target_ip": "10.0.1.1",
            "condition_name": "UDP Test",
            "scenario_type": "custom",
            "packet_count": 10,
            "ports": [53],
            "tcp_flags": "SYN",
            "response_ratio": 1.0,
            "duration_seconds": 1.0,
            "protocol": "UDP",
            "packet_size": 64
        }
        resp = self.client.post('/api/simulate', json=payload_udp)
        self.assertEqual(resp.status_code, 201)

    def test_custom_simulation_field_validation(self):
        # Invalid IP
        bad_ip = {
            "source_ip": "not-an-ip",
            "target_ip": "10.0.1.1",
            "condition_name": "Bad",
            "scenario_type": "custom",
            "packet_count": 10,
            "ports": [80],
            "tcp_flags": "SYN",
            "response_ratio": 0.0,
            "duration_seconds": 1.0,
            "protocol": "TCP",
            "packet_size": 64
        }
        resp = self.client.post('/api/simulate', json=bad_ip)
        self.assertEqual(resp.status_code, 422)

        # Invalid port
        bad_port = dict(bad_ip, source_ip="10.0.1.10", ports=[99999])
        resp = self.client.post('/api/simulate', json=bad_port)
        self.assertEqual(resp.status_code, 422)

    def test_exports_csv_and_pdf(self):
        # Create an investigation
        resp = self.client.post('/api/demo')
        self.assertEqual(resp.status_code, 201)
        inv_id = resp.json()['id']

        # CSV Export
        csv_resp = self.client.get(f'/api/investigations/{inv_id}/packets.csv')
        self.assertEqual(csv_resp.status_code, 200)
        self.assertIn("index,timestamp,source,destination", csv_resp.text)

        # PDF Export
        pdf_resp = self.client.get(f'/api/investigations/{inv_id}/report.pdf')
        self.assertEqual(pdf_resp.status_code, 200)
        self.assertTrue(pdf_resp.content.startswith(b'%PDF'))

if __name__ == '__main__':
    unittest.main()
