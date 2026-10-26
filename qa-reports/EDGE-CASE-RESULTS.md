# NetTrace Edge-Case and Boundary Analysis

**Date**: 26 October 2026  
**Auditor / Engineer**: Antigravity Principal QA & Systems Engineer  
**Scope**: Ingestion limits, file signatures, packet boundaries, malformed traffic payloads, and input sanitization.  

---

## 1. Edge-Case Matrix

| Input / Condition | Expected Behavior | Observed System Behavior | Pass/Fail | Defect Reference |
|---|---|---|---|---|
| `invalid.txt` (27 B) | Unsupported extension rejected; Analyse button disabled; clear error card. | Error shown: `Choose a .pcap or .pcapng capture.` File card shows `27 B · Unsupported file format`. Analyse disabled. | **PASS** | B07 Resolved |
| `zero-bytes.pcap` (0 B) | Empty file rejected; Analyse disabled. | Rejected: `This file is empty.` Analyse disabled. Server returns HTTP 400. | **PASS** | Validated |
| `one-syn.pcap` (94 B, 1 pkt) | Minimal capture parsed in <100ms; exactly 1 packet counted; correct TCP port. | Analyzed in 0.03s; packets_processed=1, protocol=TCP, port=80, findings=0, severity=BENIGN. | **PASS** | B02 Resolved |
| Truncated PCAP frame (truncated mid-packet) | Truncation detected promptly; clear `AnalysisError`; no hang or memory corruption. | `AnalysisError: Truncated PCAP packet data` raised; returns structured HTTP 422. | **PASS** | Validated |
| Malformed Header Magic Bytes (e.g. `b'NOTAPCAP...'`) | Signature rejected promptly; returns HTTP 422. | `AnalysisError: The file header is not a supported PCAP or PCAPNG capture.` | **PASS** | Validated |
| Oversized Capture (> 50 MiB) | File rejected before parsing; HTTP 413 Payload Too Large. | Client blocks with `Capture exceeds the 50 MiB limit.` Server stream raises HTTP 413. | **PASS** | Validated |
| Excessive Packet Count (> 100,000 pkts) | Parser safety limit enforced; memory exhaustion prevented. | `AnalysisError: Capture exceeds the 100,000 packet limit.` HTTP 422 returned. | **PASS** | Validated |
| Malformed Source IP `not-an-ip` | Immediate client-side validation error; request blocked; server returns 422. | Client displays `Invalid Source Host IP 'not-an-ip'`. Server validator rejects with 422. | **PASS** | B04 Resolved |
| Out-of-Bounds Target IP `999.999.999.999` | Rejected with clear invalid IPv4 message. | Client and server reject with invalid IPv4 format error. | **PASS** | B04 Resolved |
| Empty IP Strings / Whitespace `   ` | Treated as invalid; trimmed; field error displayed. | Form blocks submission with explicit error message. | **PASS** | B04 Resolved |
| Port Value 0 | Allowed for protocols like ICMP where ports are unused or for raw probing. | Accepted within range `0 <= p <= 65535`. | **PASS** | Validated |
| Port Value 65535 | Valid boundary port; accepted. | Synthesizer builds valid frame with port 65535. | **PASS** | Validated |
| Port Value 65536 / Non-Numeric `abc` | Rejected as out of range (1-65535) with field error. | Client displays `Port '65536' is outside the valid range 1-65535`. Server returns 422. | **PASS** | B04 Resolved |
| Protocol Switch to UDP | TCP flags selector hidden; UDP frames synthesized; sport/dport valid. | TCP flags control disappears from DOM; frames synthesized with IP proto 17. | **PASS** | Validated |
| Protocol Switch to ICMP | TCP flags selector hidden; ICMP Echo frames synthesized with type 8 code 0. | Synthesizer generates ICMP Echo request/reply pairs with IP proto 1. | **PASS** | Validated |
| Archetype Switch: Clean Web -> SYN Flood | Form fields update; slider values match valid step boundaries. | Ports updated to 80; volume=60; duration=1.5s; DOM value agrees with displayed value. | **PASS** | B06 Resolved |
| Archetype Switch: SYN Flood -> Brute Force | Duration updated to 35.0s; volume=20; ports=22. | DOM slider value is exactly 35.0s with `step="0.1"`; no drift. | **PASS** | B06 Resolved |
| Large Payload Size (1500 B MTU) | Valid frame payload generated; frame size capped at MTU. | 1500-byte Ethernet frames generated and processed without truncation errors. | **PASS** | Validated |
| VLAN 802.1Q Tagged Traffic | VLAN tag unwrapped (EtherType 0x8100); payload protocol decoded. | 802.1Q tags stripped in `packet_reader.py`; TCP packets inside VLAN 100/200 parsed. | **PASS** | Validated |
| IPv6 Traffic | IPv6 40-byte header decoded; NextHeader parsed (TCP/UDP); addresses formatted. | IPv6 addresses extracted correctly; port scan detected across IPv6 addresses. | **PASS** | Validated |
| Multi-packet Retransmissions | Repeated packets with identical flow & TCP seq counted once. | Deduplication verified; findings accurately report unique initial attempts. | **PASS** | Validated |

---

## 2. Robustness and Resource Protection Review

1. **Memory Safety**:
   - `read_packets` reads PCAP packet records iteratively rather than slurping entire captures into unconstrained byte arrays.
   - Per-frame safety limit: 16 MiB max frame size prevents malformed length headers from causing large allocations.
   - Capture packet ceiling: `MAX_PACKETS = 100_000` prevents infinite loop captures from consuming server CPU/RAM.
2. **Execution Bounding**:
   - Every analysis operation runs under `concurrent.futures.ThreadPoolExecutor` governed by `TIMEOUT = 120`.
   - On completion or failure, temporary PCAP files are deleted using `unlink(missing_ok=True)` in `finally:` blocks.
3. **Database Concurrency**:
   - SQLite access wrapped in `@contextmanager connect()` guaranteeing transactions are committed and connections are closed, preventing leaked locks or dangling file handles.
