# Rule Test Notes

## Sigma

The Sigma rules require normalized Windows telemetry:

- `windows_lsass_cross_process_access.yml`: Sysmon Event ID 10 or an equivalent
  EDR process-access event with source image, target image, and granted access.
- `windows_suspicious_process_dump_command.yml`: Sysmon Event ID 1, Windows
  Security Event ID 4688 with command-line auditing, or equivalent EDR process
  creation telemetry.

Expected benign scenarios should be tested with approved endpoint security,
debugging, crash-dump, and incident-response tooling.

## YARA

Test against:

1. Authorized reference samples in an isolated analysis environment.
2. A representative clean Windows software corpus.
3. Packed and unpacked variants where legally available.

The repository intentionally excludes test binaries and memory dumps.

