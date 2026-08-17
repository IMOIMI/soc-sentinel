# Incident Report: Scheduled task persistence with payload execution

- Alert ID: `log-scheduled-task-persistence`
- Severity: `CRITICAL`
- Score: `80/100`
- Source: `log_analysis`
- Created At: `2026-08-17T08:17:22Z`
- MITRE Techniques: `T1053.005, T1204`
- Evidence Hash: `7d231912c3b3ac609754dfcd270ce56d6f9da07def08682437ee87a0a8037d9b`

## Executive Summary

Task \Microsoft\Windows\UpdateHealth\WinUpdateCheck created persistence and executed C:\ProgramData\WindowsUpdate\updater.exe.

## Evidence

- **scheduled_task_created_microsoft_windows_updatehealth_winupdatec** (+35)
  - Location: `\Microsoft\Windows\UpdateHealth\WinUpdateCheck`
  - Reason: Scheduled task created: \Microsoft\Windows\UpdateHealth\WinUpdateCheck
- **task_points_to_writable_programdata_payload_c_programdata_window** (+20)
  - Location: `C:\ProgramData\WindowsUpdate\updater.exe`
  - Reason: Task points to writable ProgramData payload: C:\ProgramData\WindowsUpdate\updater.exe
- **scheduled_task_payload_executed_after_creation** (+25)
  - Location: `evt-012`
  - Reason: Scheduled task payload executed after creation

## Indicators

- `host`: `WIN-SOC-01` - Affected host
- `user`: `WIN-SOC-01\emmanuel` - User account
- `scheduled_task`: `\Microsoft\Windows\UpdateHealth\WinUpdateCheck` - Scheduled task
- `process`: `C:\Windows\System32\schtasks.exe` - Process image
- `user`: `NT AUTHORITY\SYSTEM` - User account
- `process`: `C:\ProgramData\WindowsUpdate\updater.exe` - Process image
- `signal`: `\Microsoft\Windows\UpdateHealth\WinUpdateCheck` - Scheduled task created: \Microsoft\Windows\UpdateHealth\WinUpdateCheck
- `signal`: `C:\ProgramData\WindowsUpdate\updater.exe` - Task points to writable ProgramData payload: C:\ProgramData\WindowsUpdate\updater.exe
- `signal`: `evt-012` - Scheduled task payload executed after creation

## Timeline

- `2026-08-17T08:17:22Z` `evt-010` event=4698 host=WIN-SOC-01 user=WIN-SOC-01\emmanuel - A scheduled task was created.
- `2026-08-17T08:17:51Z` `evt-011` event=1 host=WIN-SOC-01 user=WIN-SOC-01\emmanuel - Process Create.
- `2026-08-17T08:48:04Z` `evt-012` event=1 host=WIN-SOC-01 user=NT AUTHORITY\SYSTEM - Process Create.

## Recommended Actions

- Delete the scheduled task
- Hash and quarantine the payload
- Hunt for matching task names and payload paths across endpoints
