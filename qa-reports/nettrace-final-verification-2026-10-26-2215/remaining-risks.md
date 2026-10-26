# Remaining Risks & Operational Guidance

**Date**: 26 October 2026  
**Status**: Release Candidate Evaluation

---

## 1. Residual Risks & Technical Constraints

| Risk / Limitation | Severity | Operational Impact | Mitigation & Guidance |
|---|---|---|---|
| **Serverless Multi-Instance SQLite Ephemerality** | Low (P2) | In a multi-tenant cloud or multi-device scenario, investigations created on device A will not automatically appear on device B because Vercel serverless containers do not share a persistent central SQL database without a provisioned external database (e.g. Supabase, Turso, Neon). | **Mitigated**: The application's Dual-Tier Forensic Session architecture stores the full investigation history and records in the browser's `localStorage`. Investigations persist reliably across browser refreshes, tab closures, and work sessions on the user's workstation. The UI explicitly discloses this session-based forensic model. |
| **Custom Traffic Synthesizer Protocol Scope** | Low (P2) | The custom condition builder synthesizes IPv4 frames (TCP, UDP, ICMP) and does not currently synthesize raw IPv6 frames from the custom input form. | **Mitigated**: UI labels explicitly specify IPv4, client validation intercepts IPv6 with guidance, and native IPv6 analysis is fully supported and validated via Preset 06 (`06_ipv6_network_traffic.pcap`). |
| **Encrypted Payload Inspection Boundary** | Informational | NetTrace is a packet header forensic and behavioral telemetry analysis tool; it does not perform TLS decryption of encrypted application payloads (e.g. HTTPS HTTP/2 data streams). | **Accepted Industry Standard**: Network intrusion detection standards (CIC-IDS2017, UNSW-NB15) classify threats based on inter-arrival periodicity, port entropy, flag ratios, and flow volume without breaking TLS encryption. |

---

## 2. Release Recommendation: **GO**

With all P0 detection-accuracy defects resolved, probability distribution contradictions eliminated, privacy disclosures strictly verified against implementation, and full regression test coverage confirmed:
**The codebase is release-ready for deployment.**
