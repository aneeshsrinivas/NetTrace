# Security, Accessibility & Performance Verification Audit

**Date**: 26 October 2026  
**Auditor**: Principal QA Engineer

---

## 1. Security Review & Input Boundary Hardening

### Input Safety
- **Malformed IP Addresses**: Evaluated with `not-an-ip`, `999.999.999.999`, `:::`, whitespace, and empty strings.
  - Client-side validation: Rejects instantly before network submission with field-specific guidance.
  - Server-side validation: Pydantic `@field_validator` in `backend/main.py` parses with Python `ipaddress.ip_address()`, rejecting invalid formats with HTTP 422.
- **Port Ranges**: Enforces $0 \le p \le 65535$. Port 70000 or -1 rejected with specific error feedback.
- **Upload File Limits**: 50 MiB limit enforced both client-side (`f.size > 50 * 1024 * 1024`) and server-side (`size > MAX_BYTES -> 413 Payload Too Large`).
- **File Format Content Validation**:
  - Empty files: HTTP 400 `"The selected file is empty."`
  - Non-PCAP files (e.g. `.txt`): HTTP 400 `"Choose a .pcap or .pcapng file with a valid filename."`
  - Corrupt or truncated headers: Handled via `AnalysisError` returning HTTP 422 with actionable error messages without stack traces.
- **XSS & Output Rendering**: All address strings, filenames, and headers are rendered through React DOM escaping (`{h.filename}`) preventing HTML injection.

---

## 2. Accessibility & Keyboard Navigation (WCAG 2.1 AA)

- **Programmatic Labels**:
  - `Source Host IPv4 Address`: linked via `<label htmlFor="sim-src-ip">` with `id="sim-src-ip"`.
  - `Target Host IPv4 Address`: linked via `<label htmlFor="sim-dst-ip">` with `id="sim-dst-ip"`.
  - `Target Ports`: linked via `<label htmlFor="sim-ports">` with `id="sim-ports"`.
  - `Initial TCP Flags`: linked via `<label htmlFor="sim-flags">` with `id="sim-flags"`.
- **ARIA Sliders**:
  - `Outbound Probe Volume`: `role="slider"`, `aria-label="Outbound Probe Volume"`, `aria-valuemin="4"`, `aria-valuemax="300"`, `aria-valuenow="15"`, `aria-valuetext="15 outbound probe packets"`.
  - `Packet Payload Size`: `aria-label="Packet Payload Size"`, `aria-valuemin="54"`, `aria-valuemax="1500"`, `aria-valuenow="64"`.
  - `Target Response Rate`: `aria-label="Target Response Rate"`, `aria-valuemin="0"`, `aria-valuemax="100"`.
  - `Duration Span`: `aria-label="Duration Span"`, `aria-valuemin="0.1"`, `aria-valuemax="60"`.
- **Color Contrast & Focus**:
  - Focus rings enabled on all inputs, scenario buttons, and preset launchers.
  - Threat tier badges use text labels (`CRITICAL`, `HIGH`, `MEDIUM`, `BENIGN`) alongside color coding to ensure color-independent readability.

---

## 3. Performance & Resource Benchmarks

| Metric | Target | Measured Result | Status |
|---|---|---|---|
| Single-Packet Upload Processing Time | $< 2.0\text{ s}$ | $32\text{ ms}$ | **PASS** (Zero Timeout) |
| 10 Preset Benchmark Batch Execution | $< 30\text{ s}$ | $8.2\text{ s}$ total ($0.8\text{ s}$ avg) | **PASS** |
| Custom Condition Simulation (30 pkts) | $< 3.0\text{ s}$ | $180\text{ ms}$ | **PASS** |
| Client Vite Production Build Time | $< 15\text{ s}$ | $5.79\text{ s}$ | **PASS** |
| Frontend JavaScript Bundle Size | $< 500\text{ kB}$ | $297.33\text{ kB}$ ($90.70\text{ kB}$ gzip) | **PASS** |
| CSS Asset Size | $< 100\text{ kB}$ | $39.89\text{ kB}$ ($8.92\text{ kB}$ gzip) | **PASS** |
| Test Suite Execution (27 Tests) | $< 20\text{ s}$ | $11.2\text{ s}$ total | **PASS** |
