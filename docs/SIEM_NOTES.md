# SIEM / EDR Notes (optional extension)

Even without a full SIEM, the workflow is valid:
- Sysmon provides high-quality endpoint telemetry
- EVTX exports create portable evidence

If you add Splunk/Elastic later, correlate by:
- host + time window from meta.json
- Image / CommandLine for the executed technique
- RUN_ID embedded in command.txt and evidence artifacts
