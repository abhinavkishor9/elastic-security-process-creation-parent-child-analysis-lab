# Timeline — Suspicious Process Creation & Parent-Child Analysis

## Investigation Timeline

| Time | Activity | Process | Parent | User | Evidence / Notes |
|---|---|---|---|---|---|
| 15:57:55.260 | Controlled command-shell execution | `cmd.exe` | `pwsh.exe` | `Dell` | `/c whoami.exe`, PID `21172`, parent PID `36120` |
| 15:57:55.296 | Controlled child execution | `whoami.exe` | `cmd.exe` | `Dell` | Separate `whoami.exe` process telemetry observed |
| 15:58:06.140 | Controlled command-shell execution | `cmd.exe` | `pwsh.exe` | `Dell` | `/c hostname.exe`, PID `13388`, parent PID `36120` |
| 15:58:53.620 | Additional `whoami.exe` activity | `whoami.exe` | Validate from telemetry | `Dell` | Additional endpoint event observed |
| 16:03:54.393 | Existing endpoint activity | `cmd.exe` | `updater.exe` | `SYSTEM` | McAfee WebAdvisor-related command line |
| 16:03:54.435 | Existing endpoint activity | `cmd.exe` | `updater.exe` | `SYSTEM` | Additional updater-related command line |

## 15:57:55 — Controlled `whoami.exe` Chain

PowerShell launched:

```text
cmd.exe /c whoami.exe
```

Elastic recorded:

```text
cmd.exe
PID: 21172
Parent: pwsh.exe
Parent PID: 36120
User: Dell
```

Command line:

```text
"C:\Windows\System32\cmd.exe" /c whoami.exe
```

A separate `whoami.exe` event followed at:

```text
15:57:55.296
```

This provided evidence supporting the process chain:

```text
pwsh.exe
    |
    +-- cmd.exe
           |
           +-- whoami.exe
```

## 15:58:06 — Controlled `hostname.exe` Command

PowerShell launched:

```text
cmd.exe /c hostname.exe
```

Elastic recorded:

```text
cmd.exe
PID: 13388
Parent: pwsh.exe
Parent PID: 36120
User: Dell
```

Command line:

```text
"C:\Windows\System32\cmd.exe" /c hostname.exe
```

The command returned:

```text
DESKTOP-9MMM37V
```

However, a standalone `hostname.exe` process event was not returned by the dedicated process-name query.

The timeline therefore records:

```text
pwsh.exe
    |
    +-- cmd.exe /c hostname.exe
```

rather than claiming a confirmed independent `hostname.exe` telemetry event.

## 15:58:53 — Additional `whoami.exe` Activity

An additional event was observed:

```text
Sep 23, 2026 @ 15:58:53.620
```

with:

```text
Process: whoami.exe
Executable: C:\Windows\System32\whoami.exe
User: Dell
```

This was considered additional endpoint telemetry and was not automatically attributed to the earlier controlled event without stronger process-correlation evidence.

## 16:03:54 — Existing `updater.exe → cmd.exe` Activity

Elastic recorded two `cmd.exe` events:

```text
16:03:54.393
16:03:54.435
```

Both showed:

```text
Parent: updater.exe
Parent PID: 5868
User: SYSTEM
```

The command lines referenced:

```text
C:\Program Files\McAfee\WebAdvisor\
```

This activity occurred separately from the controlled lab commands.

It demonstrates why parent-child relationships must be considered together with timestamps, users, and command-line context.

## Key Process Chains

### Controlled `whoami.exe`

```text
pwsh.exe
    |
    +-- cmd.exe
           |
           +-- whoami.exe
```

### Controlled `hostname.exe` Command

```text
pwsh.exe
    |
    +-- cmd.exe /c hostname.exe
```

### Existing Endpoint Activity

```text
updater.exe
    |
    +-- cmd.exe
```

## Timeline Assessment

The controlled activity successfully demonstrated process creation and parent-child analysis.

The `whoami.exe` chain was supported by process telemetry.

The `hostname.exe` command was visible through the `cmd.exe` command line, but a standalone `hostname.exe` event was not observed.

Additional `updater.exe → cmd.exe` activity was present on the endpoint and was separated from the controlled activity using execution time, parent process, user context, and command-line evidence.

## Final Assessment

```text
Controlled PowerShell command
        ↓
cmd.exe observed
        ↓
Parent PID validated
        ↓
whoami.exe child observed
        ↓
hostname.exe command-line evidence observed
        ↓
Existing endpoint activity separated
        ↓
Telemetry limitation documented
```

No malicious payload, persistence, privilege escalation, command-and-control, or confirmed compromise was demonstrated.
