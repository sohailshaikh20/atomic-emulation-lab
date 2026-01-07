# Demo Guide (interview-ready)

## 0) Setup (show quickly)
- Show VM snapshot list (clean baseline)
- Show Sysmon service running + Sysmon Operational log exists
- Show Atomic installed: `Invoke-AtomicTest -AtomicTechnique T1016 -ShowDetails`

## 1) Run playbook wrapper (30 seconds)
- Run `run_playbook_with_evidence.ps1`
- Point to RUN_ID printed and evidence folder created

## 2) Show defender telemetry (Sysmon) (60–90 seconds)
- Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
- Filter Event ID 1 (Process Create)
- Show fields: Image, CommandLine, ParentImage, Hashes, UtcTime

## 3) Collect & analyze (60 seconds)
- Run `collect_telemetry.ps1` and show exported files
- Run `analyze_evidence.ps1` and open `detection_summary.json`

## 4) Explain auditability (30 seconds)
- RUN_ID ties together: command.txt ↔ atomic_output.log ↔ sysmon.evtx ↔ detection_summary.json
- `manifest.sha256` verifies evidence integrity

## Optional: SIEM/EDR
- If you have Splunk/Elastic, search by host + time window + commandline keywords.
