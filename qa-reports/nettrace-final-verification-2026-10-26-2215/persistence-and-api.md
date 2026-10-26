# Investigation Persistence & API Verification Audit

**Date**: 26 October 2026  
**Component**: Storage Architecture (`backend/main.py`) & Client Forensic Store (`frontend/src/App.tsx`)

---

## 1. Architecture of Investigation Persistence

### The Serverless Stateless Constraint
Vercel serverless functions execute inside ephemeral AWS Lambda execution contexts. Each container operates an isolated, in-memory volatile `/tmp` volume.
When requests are distributed across multiple serverless containers:
- Container A writes an investigation record to `/tmp/nettrace.sqlite3`.
- A subsequent `GET /api/investigations` request routed by the edge proxy to Container B queries Container B's local `/tmp/nettrace.sqlite3`.
- Container B returns only the investigations written to Container B (or an empty list if Container B was recently cold-started).

### Implemented Dual-Tier Persistence Architecture

To guarantee that investigations are 100% retrievable across refreshes without data loss, NetTrace uses a **Dual-Tier Forensic Session Model**:

1. **Client Forensic Session Store (`localStorage`)**:
   - `nettrace_archive_history_v1`: Stores ordered array of `{ id, filename, analyzed_at, sha256, packet_count, finding_count }`.
   - `nettrace_inv_v1_{id}`: Stores the complete, immutable `Investigation` record JSON (packets, summary, findings, classifications).
   - Survives browser page refreshes, tab closures, and multi-day browser sessions.
2. **Server Synchronizer Endpoint (`POST /api/investigations/sync`)**:
   - Whenever an investigation is created or reopened, the client transparently synchronizes the investigation metadata and packet structures to the active backend container.
   - Upserts into `investigations` SQLite table so that server-side export routes (`/api/investigations/{id}/report.pdf`, `/api/investigations/{id}/packets.csv`) remain hot and ready to serve.
3. **Resilient Client Export Fallback**:
   - If `/api/investigations/{id}/packets.csv` encounters a container rotation or cold start, the client generates the exact RFC 4180 CSV export directly in-memory from `current.packets` and triggers instant browser download.
4. **Transparent Archive User Interface**:
   - The UI explicitly states: *"Reopen recent investigations from your persistent browser forensic session cache or ephemeral backend state."*
   - Avoids false representations of permanent external cloud databases.

---

## 2. API Endpoint Verification Matrix

| Endpoint | Method | Status Code | Verified Behavior |
|---|---|---|---|
| `/api/health` | GET | 200 | Returns `{"status":"ready"}`. |
| `/api/test-presets` | GET | 200 | Returns all 10 scenario definitions with expected findings and categories. |
| `/api/test-presets/{id}/run` | POST | 201 | Executes benchmark capture; returns complete `Investigation` with SHA-256. |
| `/api/investigations` | GET | 200 | Returns list of investigations in active database container. |
| `/api/investigations/{id}` | GET | 200 / 404 | Returns complete record by ID. |
| `/api/investigations/sync` | POST | 200 | Upserts client-cached investigation record into SQLite container storage. |
| `/api/investigations` | POST | 201 | Accepts `.pcap`/`.pcapng` upload up to 50 MiB. Unlinks temporary file upon analysis. |
| `/api/simulate` | POST | 201 / 422 | Synthesizes custom traffic condition; rejects invalid IPs and port bounds. |
| `/api/ml/info` | GET | 200 | Returns model provenance, accuracy (0.934), F1 score, and feature importances. |
| `/api/investigations/{id}/packets.csv` | GET | 200 | Exports CSV packet log with standard columns. |
| `/api/investigations/{id}/report.pdf` | GET | 200 | Exports valid binary `%PDF` forensic dossier. |
