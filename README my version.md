# elastic-security-process-creation-parent-child-analysis-lab

## Overview

A process name by itself provides limited context. A SOC analyst should also examine:

Child Process
    ↓
Parent Process
    ↓
Grandparent Process
    ↓
User Context
    ↓
Command Line
    ↓
Executable Path

For example:

explorer.exe
    ↓
powershell.exe
    ↓
cmd.exe
    ↓
whoami.exe

This is not automatically malicious. The analyst must determine why the chain occurred, who initiated it, what arguments were used, and what the child process actually did.

This lab investigates **Windows process creation and parent-child process relationships** using Elastic Security and Elastic Defend.

Process names alone provide limited investigative context. A SOC analyst needs to understand which process launched another process, what command-line arguments were used, which user executed the activity, where the executable was located, and what other processes appeared around the same time.

For this lab, a controlled process chain was generated from PowerShell:

```text
pwsh.exe
    |
    +-- cmd.exe
           |
           +-- whoami.exe
```

A second command used:

```text
pwsh.exe
    |
    +-- cmd.exe
           |
           +-- hostname.exe
```

Elastic endpoint telemetry was then used to validate the observed process relationships and compare the controlled activity with other `cmd.exe` activity already present on the endpoint.

## Lab Environment

| Component | Details |
|---|---|
| Endpoint | Windows 10 Pro 22H2 |
| Host | `DESKTOP-9MMM37V` |
| User | `Dell` |
| Elastic Platform | Elastic Security Serverless |
| Endpoint Integration | Elastic Defend |
| Elastic Agent | `9.5.4` |
| Agent Policy | `Windows-SOC-Lab` |
| Investigation Interface | Discover / ES|QL |
| Shell | PowerShell 7.6.6 |

# Lab Objectives

The objectives of this lab are to:

- Understand how **Windows process creation** can be investigated from a SOC analyst perspective.
- Reconstruct **parent-child process relationships** using process names, PIDs, timestamps, and command-line data.
- Identify the parent process responsible for launching `cmd.exe` and examine the processes initiated from it.
- Investigate the controlled execution of `whoami.exe` and `hostname.exe` through `cmd.exe`.
- Correlate process execution with the associated **user, host, executable path, and command-line arguments**.
- Distinguish controlled lab activity from unrelated processes already running on the endpoint.
- Examine how broad parent-process searches can introduce unrelated telemetry and require additional filtering.
- Investigate situations where expected child-process telemetry is missing or incomplete.
- Use available telemetry to distinguish **confirmed observations from assumptions or unknowns**.
- Identify process relationships that may warrant further investigation without automatically classifying them as malicious.
- Apply an evidence-driven approach to **process ancestry and execution analysis**.
- Map the observed Windows command-shell behavior to the appropriate **MITRE ATT&CK technique**.
- Document telemetry limitations and explain how they affect the confidence of the investigation.
  
# Lab Scenario

A SOC analyst is investigating a Windows endpoint where several processes have been created through command-line execution. The analyst needs to determine whether the observed process relationships are expected administrative activity or behavior that requires further investigation.

The investigation focuses on the relationship between **PowerShell, `cmd.exe`, and standard Windows utilities**. Rather than treating individual process names as suspicious on their own, the analyst examines how each process was launched and how the processes are connected.

For the controlled investigation, commands are executed from PowerShell to generate known-good telemetry:

```text
pwsh.exe
    |
    +-- cmd.exe
           |
           +-- whoami.exe
```

A second execution uses `hostname.exe` through `cmd.exe` to determine whether the complete process chain is visible in Elastic endpoint telemetry.

The analyst then reviews:

- Parent and child process names and PIDs
- Command-line arguments
- User and host context
- Executable paths
- Execution timestamps
- Other processes associated with the same parent
- Differences between controlled activity and pre-existing endpoint activity

During the investigation, some expected process telemetry may not appear as a separate event, requiring the analyst to distinguish **what was directly observed from what was only present in a command line**.

The scenario is intentionally benign and is designed to demonstrate how a SOC analyst reconstructs process ancestry, validates telemetry, and reaches an assessment based on available evidence rather than assumptions.

## Controlled Activity

The first command returned:

```text
desktop-9mmm37v\dell
```

The second command returned:

```text
DESKTOP-9MMM37V
```

The commands were executed intentionally and did not contain malicious payloads.

## Initial Process Investigation

A focused process query was used:

```esql
FROM logs-*
| WHERE process.name IN ("cmd.exe", "whoami.exe", "hostname.exe")
| KEEP @timestamp, host.name, user.name, process.name, process.pid, process.parent.name, process.parent.pid, process.command_line, process.executable
| SORT @timestamp DESC
```

The query returned four relevant results.

Observed controlled activity included:

```text
15:57:55.260
cmd.exe
Parent: pwsh.exe
Command: "C:\Windows\System32\cmd.exe" /c whoami.exe
User: Dell
```

```text
15:57:55.296
whoami.exe
Parent: cmd.exe
User: Dell
```

A second controlled command was recorded:

```text
15:58:06.140
cmd.exe
Parent: pwsh.exe
Command: "C:\Windows\System32\cmd.exe" /c hostname.exe
User: Dell
```

The `hostname.exe` command was visible inside the `cmd.exe` command line, but a standalone `hostname.exe` process event was not returned by the focused process-name query.

## Validated Process Chain

The strongest confirmed process relationship was:

```text
pwsh.exe
    |
    +-- cmd.exe
           |
           +-- whoami.exe
```

The `cmd.exe` event showed:

```text
PID: 21172
Parent PID: 36120
Parent: pwsh.exe
```

The `whoami.exe` event was associated with the controlled execution and showed `cmd.exe` as its parent.

## Hostname Execution

The second command was:

```powershell
cmd.exe /c hostname.exe
```

Elastic recorded:

```text
cmd.exe
Command: "C:\Windows\System32\cmd.exe" /c hostname.exe
Parent: pwsh.exe
PID: 13388
Parent PID: 36120
User: Dell
```

However, the dedicated query:

```esql
FROM logs-*
| WHERE process.name == "hostname.exe"
```

returned no results.

The investigation therefore does not claim a standalone `hostname.exe` process event was captured.

Instead, the evidence supports that `hostname.exe` was passed to `cmd.exe` as part of the executed command line.

## Broader Parent-Child Hunting

A focused parent query:

```esql
FROM logs-*
| WHERE process.parent.name == "cmd.exe"
| KEEP @timestamp, host.name, user.name, process.name, process.pid, process.parent.name, process.parent.pid, process.command_line, process.executable
| SORT @timestamp DESC
```

returned four events.

The results included:

- Controlled shell activity associated with the lab.
- `conhost.exe` activity under `SYSTEM`.
- Other existing endpoint activity.

This demonstrated that broad parent-process searches can contain unrelated processes and therefore require timestamp, user, PID, command-line, and process-path validation.

## Existing Endpoint Activity

The investigation also identified existing `cmd.exe` activity associated with:

```text
updater.exe
```

under:

```text
SYSTEM
```

Observed examples included:

```text
Sep 23, 2026 @ 16:03:54.393
cmd.exe
Parent: updater.exe
Parent PID: 5868
User: SYSTEM
```

and:

```text
Sep 23, 2026 @ 16:03:54.435
cmd.exe
Parent: updater.exe
Parent PID: 5868
User: SYSTEM
```

The command lines referenced file operations under:

```text
C:\Program Files\McAfee\WebAdvisor\
```

These events were treated as **existing endpoint activity**, not as part of the controlled lab chain.

## Key Findings

### Observed

- `pwsh.exe` launched `cmd.exe` during the controlled activity.
- `cmd.exe` launched `whoami.exe`.
- `cmd.exe` was also observed with `hostname.exe` in its command line.
- The controlled events were associated with user `Dell`.
- The controlled executables were located under `C:\Windows\System32`.
- Elastic captured process IDs and parent process IDs for the controlled chain.
- Broader process queries returned unrelated endpoint activity.
- Existing `updater.exe → cmd.exe` activity was observed under `SYSTEM`.
- A standalone `hostname.exe` process event was not returned.

### Confirmed

- The controlled `pwsh.exe → cmd.exe → whoami.exe` relationship was supported by endpoint telemetry.
- The controlled `cmd.exe /c hostname.exe` command was recorded in process command-line telemetry.
- The Elastic Agent remained healthy during the investigation.
- The commands were intentionally generated and benign.

### Not Demonstrated

- Malware execution
- Persistence
- Credential theft
- Privilege escalation
- Command-and-control
- Defense evasion
- Confirmed compromise

## Telemetry Limitation

The investigation showed an important telemetry limitation.

The following query returned no standalone `hostname.exe` event:

```esql
FROM logs-*
| WHERE process.name == "hostname.exe"
```

However, the `cmd.exe` event clearly contained:

```text
/c hostname.exe
```

Therefore, the investigation records the command-line evidence without claiming that a separate `hostname.exe` process event was captured.

This distinction is important when working with endpoint telemetry.

## MITRE ATT&CK

### T1059.003 — Command and Scripting Interpreter: Windows Command Shell

The controlled activity demonstrated Windows command shell execution through `cmd.exe`.

The mapping describes the observed command-shell behavior and does not indicate that the controlled activity itself was malicious.

