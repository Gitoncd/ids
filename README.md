# ids

# Log-Based Intrusion Detection System (LIDS)

A small, offline, log-based IDS written in C# (.NET 10). It analyzes an SSH
authentication log and a web server access log, raises alerts for suspicious
patterns, and explains why each alert was generated.

Built for the Intrusion Detection Systems course (Project 1) 

> **Defensive, offline tool.** It only reads the log files you give it. It
> does not attack anything, connect to any server, or block traffic.
> The included logs are **synthetic teaching data**, not from a real server.

## What it detects

**SSH log (`auth.log`)**
- 3 or more `Failed password` events from the same IP across the whole file.
- `Accepted password` events are counted separately and never as failures.
- Blank lines and comment lines are skipped.

**Web access log (`access.log`)**
- 3 or more HTTP 401 responses from the same IP.
- Indicators of: SQL injection (`UNION` + `SELECT`), path traversal
  (`../`, `..\`, and URL-encoded forms), XSS (`<script`), and `javascript:` URLs.
- Malformed lines are counted and skipped without crashing.
- Summary: total lines, valid records, malformed lines, and HTTP status counts.

Every alert shows the rule, line number, source IP, and a short reason.

## Project structure

```
ids/
├── data/       auth.log, access.log        (synthetic sample logs)
├── src/Lids/   Program.cs, Alert.cs, Lids.csproj
├── tests/      auth_threshold.log, auth_blank_comment.log, access_test.log
└── report/     written report and program output
```

## Requirements

- [.NET 10 SDK](https://dotnet.microsoft.com/download)

## How to run

From the project root (the folder that contains `data/` and `src/`):

```
dotnet run --project src/Lids
```

To analyze other files, pass the auth log first and the access log second:

```
dotnet run --project src/Lids -- <path-to-auth.log> <path-to-access.log>
```

## Tests

| # | Command | Expected result |
|---|---------|-----------------|
| 1 | `dotnet run --project src/Lids -- tests/auth_threshold.log data/access.log` | Alert for 198.51.100.1 (3 failures, line 4); no alert for 198.51.100.2 (2 failures) |
| 2 | `dotnet run --project src/Lids -- tests/auth_blank_comment.log data/access.log` | No crash; 1 failure counted; 3 accepted logins not counted; no alert |
| 3 | `dotnet run --project src/Lids -- data/auth.log tests/access_test.log` | 401 alert for 198.51.100.10 (3), none for 198.51.100.11 (2); 1 malformed line out of 7; SQL injection alert at line 7 (lowercase) |

## Results on the sample logs

| Check | Result |
|-------|--------|
| SSH alert | 192.168.1.50 with 7 failed attempts (third failure at line 5) |
| HTTP 401 alert | 203.0.113.60 with 4 responses (203.0.113.61 had 2, so no alert) |
| Suspicious requests | SQL injection (line 4), path traversal (lines 5 and 16), XSS (line 6), javascript: URL (line 15) |
| Access log summary | 17 lines, 16 valid, 1 malformed |
| HTTP status codes | 200: 5, 400: 3, 401: 6, 403: 2 |

## Limitations

- Alerts are **indicators**, not proof of a successful attack. A suspicious
  request string, or a 400/403 response, does not show whether the application
  was vulnerable or exploited.
- Simple string matching can be evaded (for example by double URL-encoding) and
  can raise false positives (for example a harmless search for "union select").
- Counting is done over the whole file, not over a time window, and each log
  file supports only one format.
- Planned improvement: a 60-second sliding window for SSH failures.

## Disclaimer

Educational project using synthetic data only. The IP addresses in
203.0.113.0/24 are reserved for documentation and cannot identify real hosts.
