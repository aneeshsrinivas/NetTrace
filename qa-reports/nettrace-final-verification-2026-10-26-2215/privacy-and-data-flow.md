# Privacy Disclosures & Forensic Data-Flow Architecture

**Date**: 26 October 2026  
**Auditor**: Principal QA & Security Systems Lead

---

## 1. Network Data-Flow Trace

```
[ User Browser ]
       |
       |  1. HTTPS POST /api/investigations (Multipart capture file: .pcap / .pcapng)
       v
[ Vercel Edge Router / TLS Termination ]
       |
       v
[ Python Serverless Execution Context (FastAPI) ]
       |
       |-- 2. Writes temporary file to /tmp/nettrace-XXXXXX.pcap
       |-- 3. Analyzer parses pcap headers into structured Python dict
       |-- 4. ML Engine classifies host behavioral flow vectors
       |-- 5. FINALLY block executes: Path(temp.name).unlink(missing_ok=True)
       |      ==> Raw packet file is permanently deleted from filesystem.
       |-- 6. Structured metadata (no raw payloads) saved to SQLite table `investigations`
       |
       |  7. HTTPS 201 Response (JSON structured telemetry)
       v
[ User Browser ]
       |
       |-- 8. Stores complete Investigation in localStorage (Forensic Session Cache)
       |-- 9. Displays visual graphs, packets table, findings, ML intelligence
```

---

## 2. Privacy Claim Audit & Verification

| UI Disclosure Location | Previous Claim | Audited Defect | Remediated Copy | Verified Implementation Proof |
|---|---|---|---|---|
| Sidebar Badge | "Zero Data Leakage / 100% Local Inference" | Contradicted capture upload via POST `/api/investigations`. | **"Zero Raw Retention / In-Memory Volatile Processing"** | Source inspection confirms in-memory feature extraction with zero external API calls (no third-party LLM or egress). |
| Upload Eyebrow & Intro | "LOCAL PCAP INGESTION / 01" | Implied browser-native offline parsing without upload. | **"PCAP / PCAPNG INGESTION & FORENSICS / 01"**<br>*"Upload a packet capture to extract flow metrics, heuristic evidence, and ML behavioral classifications. Captures are transmitted securely over HTTPS, analyzed in volatile container memory, and immediately unlinked with zero raw payload retention."* | Code inspection of `backend/main.py` lines 120-135 confirms `finally: Path(path).unlink(missing_ok=True)`. |
| Methodology Section | "Runs entirely on this computer" | Contradicted API deployment. | **"Ephemeral Memory Analysis"**<br>*"NetTrace processes capture files in volatile container memory. Temporary capture buffers are immediately purged upon analysis completion. Zero raw packet payload bytes are stored or transmitted onward."* | Verified: Only header telemetry (index, timestamp, addresses, ports, protocol, length, flags) is retained in metadata JSON. |
| Footer Banner | "OFFLINE PCAP ANALYSIS · ZERO EGRESS" | Ambiguous offline claim. | **"ZERO RAW RETENTION · IN-MEMORY VOLATILE INGESTION"** | Accurately describes backend behavior. |

---

## 3. Raw Payload vs Metadata Verification

In `backend/analyzer.py`:
- Each packet row is created by unpacking headers (`ethernet`, `ip`, `tcp`/`udp`/`icmp`).
- `packets` table stores: `index`, `timestamp`, `source`, `destination`, `source_port`, `destination_port`, `protocol`, `length`, `flags`.
- Raw application layer payload data (e.g. HTTP body, encrypted TLS payloads, passwords, email text) is **not parsed, not stored, and not serialized**.
- Temporary PCAP files on disk are unlinked in `finally:` blocks for both uploads and demo/synthesizer runs.
