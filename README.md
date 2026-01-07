# Atomic Emulation Lab — Auditable ATT&CK Playbooks (Windows + Sysmon)

**Portfolio project:** Convert MITRE ATT&CK techniques into **repeatable, auditable defender exercises** using **Atomic Red Team**, **Sysmon**, and **PowerShell automation**.

✅ Reproducible runs (one command)  
✅ Evidence packages per run (RUN_ID)  
✅ Integrity verification (SHA256 manifest)  
✅ Local analysis output (`detection_summary.json`)  
✅ Designed for SIEM/EDR validation workflows

---

## Why this matters (for defenders & employers)
Security teams struggle to answer: *“Can we reliably detect common attacker behavior?”*  
This repo turns one-off atomic tests into **measurable detection benchmarks** with consistent evidence artifacts that are easy to review, share, and rerun.

---


flowchart LR
  %% Styles
  classDef control fill:#eef3ff,stroke:#4c6ef5,stroke-width:1px;
  classDef data fill:#f8f9fa,stroke:#adb5bd,stroke-width:1px;
  classDef output fill:#e6fcf5,stroke:#12b886,stroke-width:1px;

  %% Control Plane
  subgraph Control["Control Plane"]
    A[Playbook Command]
    B[Atomic Red Team Test]
  end

  %% Telemetry & Evidence
  subgraph Evidence["Telemetry and Evidence"]
    C["Telemetry (Sysmon + Windows Logs)"]
    D[Evidence Collector]
    E["Evidence Folder (RUN_ID)"]
  end

  %% Analysis & Output
  subgraph Analysis["Analysis and Reporting"]
    F[Local Analyzer]
    G["detection_summary.json"]
    H["SIEM / EDR Correlation (Optional)"]
  end

  %% Flow
  A --> B --> C --> D --> E --> F --> G --> H

  %% Styling
  class A,B control
  class C,D,E data
  class F,G,H output
---

## Architecture (high-level)

```mermaid
flowchart LR
  A[Playbook Command] --> B[Atomic Red Team Test]
  B --> C[Telemetry: Sysmon + Windows Logs]
  C --> D[Evidence Collector]
  D --> E[Evidence Folder (RUN_ID)]
  E --> F[Local Analyzer]
  F --> G[detection_summary.json]
  G --> H[Optional: SIEM/EDR Correlation]
```

---

## Repo contents
- `scripts/` — end-to-end automation
- `playbooks/` — technique descriptors (YAML) for consistent documentation
- `docs/` — demo checklist, screenshots guide, SIEM mapping notes
- `infrastructure/` — Sysmon config placeholder + install notes
- `.github/workflows/` — PowerShell linting (PSScriptAnalyzer)

---

## Quick start (Windows VM)
### 1) Prereqs
- Windows 10/11 VM (recommended: isolated / NAT)
- PowerShell 5.1+ (Admin recommended)
- Atomic Red Team installed (Invoke-AtomicTest available)
- Sysmon installed (recommended)

### 2) One-time setup (auditing + PowerShell logging)
```powershell
Set-Location .\scripts
.\enable_telemetry.ps1
```

### 3) Run a safe technique (no external payloads)
Example: **T1016 — System Network Configuration Discovery**
```powershell
.\run_playbook_with_evidence.ps1 `
  -PlaybookID "RT-ATOMIC-PORTFOLIO" `
  -TechniqueId "T1016" `
  -TestNumbers "1" `
  -PathToAtomicsFolder "C:\AtomicRedTeam\atomics" `
  -Operator "md_sohail"
```

### 4) Collect logs into evidence folder (shown by wrapper)
```powershell
.\collect_telemetry.ps1 -EvidenceFolder "C:\evidence\<RUN_ID>"
```

### 5) Analyze evidence (best-effort local analysis)
```powershell
.\analyze_evidence.ps1 -EvidenceFolder "C:\evidence\<RUN_ID>"
```

---

## Evidence output (what auditors & blue teams love)
Each run creates:
- `meta.json` — run metadata (RUN_ID, technique, operator, times)
- `command.txt` — exact executed command
- `atomic_output.log` — atomic console output
- `sysmon.evtx` — Sysmon Operational export (if installed)
- `system.evtx`, `application.evtx` — OS logs
- `security_process_creation.xml` — 4688 process creation (time-windowed)
- `manifest.sha256` — file integrity checksums
- `detection_summary.json` — analysis results

---

## Recommended demo techniques (low-risk, high signal)
Use these for interviews & recorded demos:
- **T1016** — Network Configuration Discovery
- **T1082** — System Information Discovery
- **T1057** — Process Discovery
- **T1083** — File/Directory Discovery
- **T1033** — System Owner/User Discovery

---

## Security & Safety
This is a **lab project**. Run only in a VM. Snapshot before tests. Prefer discovery techniques for demos.

---

## Roadmap (next improvements)
- Push evidence + summary to SIEM (Splunk/Elastic) via HEC/agent
- Add Sigma rules / detections tied to each playbook
- Export Sysmon events to JSON for easy cross-platform parsing
- CI: unit tests for evidence packaging + analyzer logic

---

## Recruiter-friendly highlights
- Built an **auditable adversary emulation pipeline** using ATT&CK mapping
- Automated **evidence packaging** and integrity verification (SHA256 manifests)
- Collected **defender-grade telemetry** (Sysmon + Windows logs)
- Produced **repeatable detection benchmarks** with measurable outputs

---

## License
MIT — see `LICENSE`.

> Last updated: 2026-01-07
