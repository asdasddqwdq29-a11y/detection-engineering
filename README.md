# Detection Engineering

Defensive detection content for Windows endpoint telemetry and static file
triage. Each rule includes its intended data source, limitations, and expected
false positives.

## Rules

### Sigma

- [`windows_lsass_cross_process_access.yml`](sigma/windows/windows_lsass_cross_process_access.yml)  
  Detects suspicious cross-process access to LSASS using Sysmon Event ID 10.
- [`windows_suspicious_process_dump_command.yml`](sigma/windows/windows_suspicious_process_dump_command.yml)  
  Detects common command-line patterns used to create process memory dumps.

### YARA

- [`credential_dumping_tool_indicators.yar`](yara/credential_dumping_tool_indicators.yar)  
  Identifies a combination of credential-access command strings and Windows
  security APIs in PE files.
- [`lsass_minidump_artifact.yar`](yara/lsass_minidump_artifact.yar)  
  Identifies minidump files that reference `lsass.exe`.

## Validation Philosophy

- Prefer behavior and multiple independent indicators over filenames.
- State required telemetry and rule blind spots.
- Keep static signatures narrow enough to avoid matching legitimate security
  administration tools based on one generic string.
- Test in a controlled environment using benign fixtures or authorized
  samples.
- Treat every alert as a lead that requires context, not a final verdict.

## Repository Safety

This repository contains detection logic only. It does not contain malware,
credential material, exploit payloads, or instructions for bypassing security
controls.

