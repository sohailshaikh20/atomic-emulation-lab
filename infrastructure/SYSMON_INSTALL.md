# Sysmon Install Notes (Windows VM)

1) Download Sysmon (Sysinternals) and unzip.
2) Install (Admin):
   sysmon64.exe -accepteula -i sysmonconfig_placeholder.xml
3) Verify:
   - Services: Sysmon64 running
   - Event Viewer: Sysmon Operational log
