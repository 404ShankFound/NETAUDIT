# NetAudit: Automated PCAP and Network Traffic Analysis Toolkit

**ICT 3141 — Information Security Lab**

| Team member | Registration no. | Roll no. |
|---|---:|---:|
| Shashank Nandan | 240911204 | 13 |
| Harshvir Singh | 240911678 | 58 |
| Snehal Gupta | 240911528 | 40 |

NetAudit is a lightweight academic SOC-style investigation tool. It accepts an offline `.pcap`, reads packet layers with **PyShark/TShark**, converts selected telemetry into **SQLite**, applies explainable security heuristics, displays stored results on a browser dashboard, and creates a PDF security report.

## Problem Statement

Manual Wireshark inspection is valuable but time-consuming for large or historical captures. NetAudit provides a repeatable way to turn raw PCAP traffic into searchable packet records, traffic statistics, and clearly-worded suspicious-activity alerts. It is an analysis aid; an alert is not proof of an attack.

## Architecture

```text
HTML + Tailwind + Chart.js dashboard
              ↓
        FastAPI routes
              ↓
     upload validation and storage
              ↓
   PyShark FileCapture (TShark)
              ↓
     telemetry extraction service
              ↓
    SQLAlchemy ORM → SQLite database
              ↓
   time-window statistics + rule engine
              ↓
  alerts + threat score → dashboard / PDF
```

## Features

- Validates and stores `.pcap` uploads using generated filenames and a 50 MB default limit.
- Uses `pyshark.FileCapture` for real TShark-backed protocol-layer extraction.
- Persists packets, analyses, and alert evidence in SQLite through SQLAlchemy.
- Shows protocol distribution, leading sources, leading destination ports, summary cards, findings, and packet explorer.
- Runs configurable port-scan, possible brute-force, and abnormal-volume checks over 10-second windows.
- Generates a downloadable PDF report from persisted data.
- Includes safe, offline synthetic PCAP generation for a predictable lab demo.

## Alignment with ICT 3141 Synopsis

| Mandatory module | NetAudit implementation |
|---|---|
| PCAP Analysis | Uploaded PCAP is parsed and inspected for IP, TCP, UDP, DNS, and HTTP metadata. |
| PCAP to SQLite | Extracted telemetry is stored in the `packets` table linked to `analyses`. |
| Traffic Analysis | Protocol, IP, port, volume, and time-window statistics are calculated. |
| Wireshark | Wireshark can create/inspect PCAPs; its TShark component is the protocol decoder used by PyShark. |
| PyShark | `app/services/pcap_parser.py` uses `pyshark.FileCapture` to read saved PCAPs. |

## Technology Stack

- **Backend:** Python, FastAPI
- **PCAP parsing:** PyShark with TShark; Scapy only generates harmless offline demo PCAPs
- **Storage:** SQLite, SQLAlchemy
- **Frontend:** HTML5, Tailwind CSS, Chart.js
- **Reporting:** ReportLab PDF
- **Container:** Docker Compose

## Database Structure

- `analyses`: upload metadata, completion state, packet count, duration, threat score, and stored statistics.
- `packets`: structured timestamp, packet number, source/destination IP, protocol, ports, packet length, TCP flags, DNS query, and HTTP fields.
- `alerts`: detection type, severity, source/destination, timestamp, readable evidence, and score contribution.

The database is created at `data/netaudit.db` when the app starts. The dashboard APIs query this database rather than retaining results only in memory.

## Local Setup

Prerequisite: install Wireshark with **TShark** and make `tshark` available on PATH. PyShark is an interface to TShark, so installing the Python package alone is not enough.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts/generate_demo_pcaps.py
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`. API documentation is available at `http://127.0.0.1:8000/docs`.

## Docker Setup

Docker installs TShark in the image, so no host Wireshark installation is required for container parsing.

```powershell
docker compose up --build
```

Open `http://127.0.0.1:8000`. The Compose volumes preserve the SQLite database, stored uploaded PCAPs, and generated reports on the host.

## Upload and Demo Workflow

1. Create the controlled samples: `python scripts/generate_demo_pcaps.py`.
2. Start the app locally or with Docker.
3. Upload `sample_pcaps/normal_traffic.pcap`; it should normally produce a low score.
4. Upload `sample_pcaps/port_scan.pcap`; it generates a **Possible Port Scan** alert from many destination ports in one window.
5. Upload `sample_pcaps/brute_force.pcap`; it generates **Possible Brute-Force Activity** due to repeated SSH attempts.
6. Upload `sample_pcaps/abnormal_traffic.pcap`; it generates **Abnormal Traffic Volume** after a large burst compared with calm earlier windows.
7. Show packet records, findings/evidence, charts, and click **Download PDF Report**.

The script writes packets to files only; it neither sends packets nor scans systems. Use real captures and tests only on networks where you are authorized.

## How Detection Works

Rules operate on configurable 10-second windows. This matters because a single packet is usually not suspicious, while a short burst pattern may be.

| Rule | Default threshold | Explanation | Score |
|---|---:|---|---:|
| Possible Port Scan | 15 distinct destination ports/source/window | One source contacting many different ports rapidly can indicate service enumeration. | +40 |
| Possible Brute-Force Activity | 8 TCP attempts to the same auth service/window | Repeated connections to ports 21, 22, 23, 25, 110, 143, or 3389 may indicate password guessing. | +40 |
| Abnormal Traffic Volume | 3× median bytes/window | A window is flagged when its bytes exceed the simple median baseline by the multiplier. | +30 |

The score is clamped to 0–100: **Low** 0–29, **Medium** 30–59, **High** 60–79, **Critical** 80–100. These are transparent project heuristics, not scientifically validated probabilities. Set thresholds in `.env` (copy `.env.example`) before starting the server.

## Testing

Run the detection, telemetry, and upload-to-SQLite integration tests:

```powershell
pytest -q
```

The end-to-end API test substitutes a deterministic parser stream so it verifies the web upload → SQLite persistence → detection route without needing a local TShark binary. The actual application parser remains PyShark/TShark-backed and is exercised by uploading generated PCAPs.

## Security and Error Handling

- Only `.pcap` filenames are accepted; names are discarded in favor of UUID storage names.
- Uploads are streamed to a controlled directory with a size limit; uploaded files are never executed.
- SQLAlchemy parameterization avoids hand-built SQL queries.
- Layer extraction is defensive because packet layers/fields are optional.
- User-provided strings are escaped before display in the dashboard.
- The UI receives concise errors for invalid extensions, empty/corrupt captures, missing TShark, oversized files, and report failures; detailed server diagnostics should be handled from server logs.

## Limitations

- This is offline PCAP analysis, not real-time capture or intrusion prevention.
- Encrypted HTTPS payloads cannot provide HTTP host/method/URI details unless such metadata is visible in the capture.
- Fixed heuristic thresholds can have false positives and false negatives; tune them for the lab dataset.
- It accepts classic `.pcap` only for the demo scope, not every capture format.
- The dashboard uses CDN-hosted Tailwind and Chart.js; for a completely disconnected presentation, serve pinned local copies of those two frontend libraries before the demo.

## Viva: How Each Module Works

1. **What is PCAP?** A PCAP is a file containing packets captured from a network interface.
2. **Why Wireshark?** It is a trusted packet-inspection tool that creates and visually verifies captures.
3. **What is TShark?** Wireshark’s command-line packet decoder.
4. **What is PyShark?** A Python wrapper that asks TShark to decode packets and exposes protocol layers as Python fields.
5. **Why not manually parse bytes?** Protocol layouts are complex; PyShark/TShark provides mature, readable decoding.
6. **How is information extracted?** The parser checks for optional IP/TCP/UDP/DNS/HTTP layers and copies useful fields into a compact telemetry record.
7. **What is telemetry?** Selected structured facts about traffic, such as time, IPs, ports, protocol, and size.
8. **Why SQLite?** It makes packet results durable, searchable, and easy to demonstrate without another server.
9. **How does PCAP → SQLite work?** Each PyShark packet becomes one SQLAlchemy `Packet` row linked to an `Analysis` row.
10. **How are scans detected?** Count distinct destination ports per source IP in each short window.
11. **How is possible brute force detected?** Count repeated TCP attempts from a source to a destination authentication port.
12. **How is abnormal traffic identified?** Compare a window’s bytes with the capture’s median window volume.
13. **How is the score calculated?** Add each alert’s documented contribution and cap at 100.
14. **Why heuristics?** They are deterministic and easy to test, explain, and tune for an undergraduate project.
15. **What are false positives?** Benign traffic that happens to satisfy a suspicious rule.
16. **Why is an alert not proof?** Context is required; legitimate scanners, backups, or retries can resemble attacks.
17. **Why FastAPI?** It provides concise, documented endpoints and handles uploads well.
18. **Why SQLite?** It is portable, file-based, and sufficient for a lightweight academic demo.
19. **Why Chart.js?** It turns stored numeric summaries into simple browser charts.
20. **Why Docker?** It makes the environment repeatable and includes TShark with the app.
21. **Why Scapy?** Only to generate safe, controlled offline PCAP fixtures; PyShark remains the primary parser.
22. **What are the limitations?** Offline-only analysis, fixed rules, encrypted traffic visibility limits, and no guarantee that an alert is an attack.
