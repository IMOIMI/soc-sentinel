# Incident Report: Compromised account after brute-force burst

- Alert ID: `log-bruteforce-compromise`
- Severity: `HIGH`
- Score: `75/100`
- Source: `log_analysis`
- Created At: `2026-08-17T08:14:02Z`
- MITRE Techniques: `T1110, T1078`
- Evidence Hash: `dec705a439926a390a469979152f1b2085ecdf9e20e1138338ff9e0ed8be4934`

## Executive Summary

Account emmanuel on WIN-SOC-01 had repeated failures from 198.51.100.23, then a successful logon.

## Evidence

- **5_failed_logons_for_emmanuel_from_198_51_100_23_in_under_five_mi** (+45)
  - Location: `198.51.100.23`
  - Reason: 5 failed logons for emmanuel from 198.51.100.23 in under five minutes
- **successful_logon_followed_the_failed_logon_burst_from_the_same_s** (+30)
  - Location: `evt-006`
  - Reason: Successful logon followed the failed-logon burst from the same source

## Indicators

- `host`: `WIN-SOC-01` - Affected host
- `user`: `emmanuel` - User account
- `ip`: `198.51.100.23` - Source IP
- `signal`: `198.51.100.23` - 5 failed logons for emmanuel from 198.51.100.23 in under five minutes
- `signal`: `evt-006` - Successful logon followed the failed-logon burst from the same source

## Timeline

- `2026-08-17T08:14:02Z` `evt-001` event=4625 host=WIN-SOC-01 user=emmanuel - An account failed to log on.
- `2026-08-17T08:14:17Z` `evt-002` event=4625 host=WIN-SOC-01 user=emmanuel - An account failed to log on.
- `2026-08-17T08:14:31Z` `evt-003` event=4625 host=WIN-SOC-01 user=emmanuel - An account failed to log on.
- `2026-08-17T08:14:45Z` `evt-004` event=4625 host=WIN-SOC-01 user=emmanuel - An account failed to log on.
- `2026-08-17T08:15:04Z` `evt-005` event=4625 host=WIN-SOC-01 user=emmanuel - An account failed to log on.
- `2026-08-17T08:15:36Z` `evt-006` event=4624 host=WIN-SOC-01 user=emmanuel - An account was successfully logged on.

## Recommended Actions

- Disable or reset the affected account
- Block the source IP at the perimeter
- Review successful logon session activity
