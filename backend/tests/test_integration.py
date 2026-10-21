import io
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from backend.demo import tcp_frame, write_pcap

from backend import analyzer, main

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'DB_PATH', tmp_path / 'results.sqlite3')
    return TestClient(main.app)

def capture(path, ng=False):
    records = [(1700000000+i*2, tcp_frame('10.0.0.1','10.0.0.2',40000+i,20+i,i+10)) for i in range(12)]
    write_pcap(path, records, ng)

def test_pcap_rules_and_evidence(tmp_path):
    path = tmp_path/'sample.pcap'; capture(path)
    data = analyzer.analyze(str(path), path.name)
    assert data['summary']['packets_processed'] == 12
    assert data['summary']['hosts'] == 2
    assert data['summary']['distinct_ports'] == 12
    assert {f['rule'] for f in data['findings']} == {'Port scanning', 'SYN-heavy activity'}
    assert all(set(f['evidence']) <= {p['index'] for p in data['packets']} for f in data['findings'])
    assert len(data['sha256']) == 64

def test_pcapng_and_rule_selection(tmp_path):
    path = tmp_path/'sample.pcapng'; capture(path, True)
    data = analyzer.analyze(str(path), path.name, {'port_scan': False, 'syn_heavy': True, 'repeated': False})
    assert data['summary']['packets_processed'] == 12
    assert [f['rule'] for f in data['findings']] == ['SYN-heavy activity']

def test_retransmission_deduplication(tmp_path):
    path = tmp_path/'repeat.pcap'
    frame = tcp_frame('10.0.0.1','10.0.0.2',40000,443,1)
    write_pcap(path, [(1700000000+i,frame) for i in range(12)])
    data = analyzer.analyze(str(path), path.name)
    assert data['summary']['packets_processed'] == 12
    assert not data['findings']

def test_empty_valid_capture_and_truncated_record(tmp_path):
    path = tmp_path/'empty.pcap'
    write_pcap(path, [])
    data = analyzer.analyze(str(path), path.name)
    assert data['summary']['packets_processed'] == 0
    assert data['findings'] == []
    path.write_bytes(path.read_bytes() + b'\x00')
    with pytest.raises(analyzer.AnalysisError, match='Truncated PCAP record'):
        analyzer.analyze(str(path), path.name)

def test_repeated_connections_and_observed_response(tmp_path):
    path = tmp_path/'service.pcap'
    records = [(1700000000+i*3, tcp_frame('10.0.0.1','10.0.0.2',40000+i,443,i+1)) for i in range(10)]
    records.append((1700000040,tcp_frame('10.0.0.2','10.0.0.1',443,40000,5,0x12)))
    write_pcap(path, records)
    data = analyzer.analyze(str(path), path.name)
    assert {'SYN-heavy activity','Repeated connections'} <= {f['rule'] for f in data['findings']}
    heavy = next(f for f in data['findings'] if f['rule']=='SYN-heavy activity')
    assert heavy['stats']['matched_flows'] == 1
    assert heavy['stats']['response_ratio'] == 0.1

def test_api_upload_history_and_exports(client, tmp_path):
    path = tmp_path/'sample.pcap'; capture(path)
    response = client.post('/api/investigations', files={'file': ('sample.pcap', path.read_bytes(), 'application/octet-stream')})
    assert response.status_code == 201, response.text
    data = response.json(); identity = data['id']
    assert client.get('/api/investigations').json()[0]['id'] == identity
    assert client.get(f'/api/investigations/{identity}').json()['sha256'] == data['sha256']
    csv = client.get(f'/api/investigations/{identity}/packets.csv')
    assert csv.status_code == 200 and len(csv.text.splitlines()) == 13
    assert 'index,timestamp,source,destination' in csv.text
    pdf = client.get(f'/api/investigations/{identity}/report.pdf')
    assert pdf.status_code == 200 and pdf.content.startswith(b'%PDF') and len(pdf.content) > 1000

def test_bad_inputs_and_limits(client, tmp_path, monkeypatch):
    assert client.post('/api/investigations', files={'file': ('bad.txt', b'anything')}).status_code == 400
    assert client.post('/api/investigations', files={'file': ('empty.pcap', b'')}).status_code == 400
    assert client.post('/api/investigations', files={'file': ('bad.pcap', b'not a capture')}).status_code == 422
    monkeypatch.setattr(main, 'MAX_BYTES', 10)
    assert client.post('/api/investigations', files={'file': ('big.pcap', b'0'*11)}).status_code == 413
    path = tmp_path/'sample.pcap'; capture(path)
    monkeypatch.setattr(analyzer, 'MAX_PACKETS', 3)
    with pytest.raises(analyzer.AnalysisError, match='packet limit'):
        analyzer.analyze(str(path), path.name)

def test_controlled_demo(client):
    result = client.post('/api/demo')
    assert result.status_code == 201, result.text
    data = result.json()
    assert data['filename'] == 'controlled-demo.pcap'
    assert data['summary']['packets_processed'] == 26
    assert {f['rule'] for f in data['findings']} == {'Port scanning', 'SYN-heavy activity', 'Repeated connections'}
