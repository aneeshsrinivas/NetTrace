# NetTrace Privacy and Security Review

**Date**: 26 October 2026  
**Auditor / Engineer**: Antigravity Principal Security & Forensics Engineer  
**Scope**: Data transport, storage lifecycle, privacy disclosures, boundary validation, and security posture.  

---

## 1. Resolution of Bug B03 (Privacy Claim Discrepancy)

### Baseline Conflict
The initial audit identified that the interface displayed claims including:
- "Zero Egress"
- "100% Private Offline"
- "Runs entirely on this computer"

However, network inspection confirmed that selecting a PCAP file and clicking "Analyse capture" performs a multipart HTTP POST to `/api/investigations` on the production server. While the backend did not share files with third parties, calling this "Zero Egress / 100% Offline" was inaccurate and misleading to users handling sensitive network captures.

### Resolved Architecture & Disclosures
The product architecture has been rigorously audited and its public disclosures fully aligned with actual operational behavior:

1. **Ephemeral In-Memory Processing**:
   - Capture files uploaded to `/api/investigations` are written to a temporary operating system spool file (`tempfile.NamedTemporaryFile`) strictly for iterative header parsing.
   - Raw packet payloads are never stored, logged, or indexed.
   - Upon completion of analysis or immediately upon any unhandled exception, the temporary capture file is unlinked (`Path(path).unlink(missing_ok=True)`) in a guaranteed `finally:` block.
2. **Metadata-Only Persistence**:
   - The SQLite database (`nettrace.sqlite3`) records only extracted header metadata:
     - Timestamp, source IP, destination IP, ports, protocol, frame length, TCP flags, heuristic finding descriptions, and the calculated SHA-256 byte digest.
   - No raw packet payloads or sensitive capture bytes reside in persistent storage.
3. **Disclosure Alignment Across All Views**:
   - **Overview Hero**: Updated from *"Zero Egress / 100% Private Offline"* to:
     `Private Forensics · Zero Raw Retention`
   - **Upload Intake**: Updated from *"Heuristic analysis and ML threat inference run entirely on this computer"* to:
     `"Captured frames are processed in ephemeral memory for metadata extraction with zero raw payload retention."`
   - **Methodology Page**: Clarified that NetTrace is a post-capture forensic tool processing captures in ephemeral memory without saving packet payloads or egressing traffic.
   - **Footer Banner**: Updated from *"100% OFFLINE LOCAL INVESTIGATION"* to:
     `"ZERO RAW RETENTION · METADATA-ONLY ARCHIVE"`

---

## 2. Data Flow & Transport Security

```
[ User Browser ]
       │
       │  HTTPS / TLS 1.3 (Multipart POST)
       │  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
       ▼
[ FastAPI Server / Serverless Container ]
       │
       ├── Temporary Spool File (/tmp/nettrace-*.pcap)
       │       │
       │       ├── ThreadPoolExecutor -> packet_reader.read_packets()
       │       ├── analyzer.analyze() -> Header Extraction (IP, Ports, Flags)
       │       └── ml_engine.classify_capture() -> Feature Vector Inference
       │
       ├── Temporary Spool Unlinked (File Deleted via finally block)
       │
       ▼
[ SQLite Database (/tmp/nettrace.sqlite3) ]
       └── Stores: ID, Filename, Analyzed_At, SHA-256, Packet Count, Findings, JSON Metadata Summary
           (NO RAW PACKETS / NO PAYLOADS STORED)
```

### Telemetry & External Connectivity Check
- **External Calls**: The application makes **zero** outbound telemetry calls, analytics requests, or beacon transmissions.
- **Third-Party CDNs**: All fonts (`DM Sans`, `Manrope`, `DM Mono`) are self-hosted local WOFF2 assets bundled into `frontend/dist/assets`. No Google Fonts or third-party origins are contacted at runtime.
- **Model Execution**: The Random Forest classifier executes locally in-process via scikit-learn without contacting external inference APIs.

---

## 3. Application Security Controls

### 3.1 Input Validation and Sanitization
- **File Upload Guardrails**:
  - Extensions strictly limited to `.pcap` and `.pcapng`.
  - Content length enforced at 50 MiB limit (`MAX_BYTES = 50 * 1024 * 1024`).
  - Zero-byte files rejected immediately with HTTP 400.
  - Per-frame safety cap (16 MiB) and total packet ceiling (`MAX_PACKETS = 100_000`) prevent memory exhaustion attacks.
- **Synthesizer Sanitization**:
  - `source_ip` and `target_ip` validated via Python's standard `ipaddress.ip_address` parser. Rejects invalid strings, injection attempts, and malformed octets with HTTP 422.
  - Port numbers validated to valid range (`0 <= p <= 65535`).

### 3.2 SQL Injection Prevention
- All database operations in `backend/main.py` utilize parameterized SQL queries with standard `?` parameter markers:
  ```python
  db.execute("INSERT INTO investigations VALUES (?, ?, ?, ?, ?, ?, ?)", (...))
  db.execute("SELECT data FROM investigations WHERE id=?", (investigation_id,))
  ```
- No user-controlled strings are concatenated into SQL statements.

### 3.3 Export Security & CSV Injection Mitigation
- The CSV export endpoint (`/api/investigations/{id}/packets.csv`) serializes extracted integers and IP strings using Python's `csv.DictWriter`.
- Cells are properly quoted and delimited. Extracted protocols and IP addresses cannot trigger formula execution in spreadsheet software.
- The PDF export uses ReportLab to generate valid binary PDF artifacts (`%PDF-1.4`) with sanitized labels.

---

## 4. Hardening Recommendations for Production Gateway

While the application code is secure, the following reverse-proxy HTTP headers are recommended for the production hosting gateway (Vercel / Nginx):
1. **Content-Security-Policy (CSP)**:
   `default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; script-src 'self'`
2. **X-Content-Type-Options**:
   `nosniff`
3. **X-Frame-Options**:
   `DENY`
4. **Referrer-Policy**:
   `strict-origin-when-cross-origin`
5. **Permissions-Policy**:
   `camera=(), microphone=(), geolocation=()`
