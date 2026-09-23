# Investigation Notes 

## Endpoint Validation

Fleet showed:

```text
Status: Healthy
Host: DESKTOP-9MMM37V
Policy: Windows-SOC-Lab
Agent Version: 9.5.4
```

This confirmed that the endpoint agent was active during the investigation.

## Controlled Commands

The first command was:

```powershell
cmd.exe /c whoami.exe
```

Observed output:

```text
desktop-9mmm37v\dell
```

The second command was:

```powershell
cmd.exe /c hostname.exe
```

Observed output:

```text
DESKTOP-9MMM37V
```

## Process Query

The following ES|QL query was used:

```esql
FROM logs-*
| WHERE process.name IN ("cmd.exe", "whoami.exe", "hostname.exe")
| KEEP @timestamp, host.name, user.name, process.name, process.pid, process.parent.name, process.parent.pid, process.command_line, process.executable
| SORT @timestamp DESC
```

The query returned four results.

## Observed `cmd.exe` — `whoami.exe`

At:

```text
15:57:55.260
```

Elastic recorded:

```text
Process: cmd.exe
PID: 21172
Parent: pwsh.exe
Parent PID: 36120
User: Dell
```

Command line:

```text
"C:\Windows\System32\cmd.exe" /c whoami.exe
```

This established the controlled relationship:

```text
pwsh.exe
    |
    +-- cmd.exe
           |
           +-- whoami.exe
```

A separate `whoami.exe` event was also observed:

```text
15:57:55.296
```

This provided supporting evidence for the child process.

## Observed `cmd.exe` — `hostname.exe`

At:

```text
15:58:06.140
```

Elastic recorded:

```text
Process: cmd.exe
PID: 13388
Parent: pwsh.exe
Parent PID: 36120
User: Dell
```

Command line:

```text
"C:\Windows\System32\cmd.exe" /c hostname.exe
```

The command-line field therefore provides evidence that `hostname.exe` was requested through the command shell.

## Missing `hostname.exe` Event

A dedicated query was executed:

```esql
FROM logs-*
| WHERE process.name == "hostname.exe"
| KEEP @timestamp, host.name, user.name, process.pid, process.parent.name, process.parent.pid, process.command_line, process.executable
| SORT @timestamp DESC
```

Result:

```text
No results
```

The investigation therefore does not claim that Elastic captured a standalone `hostname.exe` process event.

The available evidence supports only the following:

```text
pwsh.exe
    |
    +-- cmd.exe /c hostname.exe
```

The standalone child-process telemetry was not observed in the returned dataset.

## Parent-Process Hunting

The following query was used:

```esql
FROM logs-*
| WHERE process.parent.name == "cmd.exe"
| KEEP @timestamp, host.name, user.name, process.name, process.pid, process.parent.name, process.parent.pid, process.command_line, process.executable
| SORT @timestamp DESC
```

This returned four events.

Some results were associated with:

```text
conhost.exe
```

under:

```text
SYSTEM
```

These results were not assumed to be part of the controlled lab activity.

## Broad Shell Hunting

A broader query was used:

```esql
FROM logs-*
| WHERE process.parent.name IN ("cmd.exe", "powershell.exe", "pwsh.exe")
| KEEP @timestamp, process.name, process.pid, process.parent.name, process.parent.pid, process.command_line, user.name
| SORT @timestamp DESC
```

This returned:

```text
181 results processed
```

The large result set demonstrated that broad shell-parent queries can contain substantial unrelated activity.

## Broad Process Ancestry Query

Another query was:

```esql
FROM logs-*
| WHERE process.parent.name IS NOT NULL
| KEEP @timestamp, host.name, user.name, process.parent.name, process.name, process.parent.pid, process.pid, process.command_line, process.executable
| SORT @timestamp DESC
```

This returned:

```text
705 results processed
```

This provided visibility into the wider process landscape but required additional filtering for useful investigation.

## Existing `updater.exe → cmd.exe` Activity

The investigation found existing `cmd.exe` events at:

```text
16:03:54.393
16:03:54.435
```

Both were associated with:

```text
Parent: updater.exe
Parent PID: 5868
User: SYSTEM
```

The command lines referenced operations under:

```text
C:\Program Files\McAfee\WebAdvisor\
```

This activity was separated from the controlled lab chain based on timestamp, parent process, user context, and command-line content.

## Process Chain Comparison

### Controlled activity

```text
pwsh.exe
    |
    +-- cmd.exe
           |
           +-- whoami.exe
```

### Controlled hostname command

```text
pwsh.exe
    |
    +-- cmd.exe /c hostname.exe
```

### Existing endpoint activity

```text
updater.exe
    |
    +-- cmd.exe
```

These different chains demonstrate why process ancestry needs context.

## Analyst Assessment

### Observed

- Controlled `cmd.exe` executions.
- `pwsh.exe → cmd.exe` relationships.
- `cmd.exe → whoami.exe` relationship.
- `hostname.exe` referenced in the `cmd.exe` command line.
- Existing `updater.exe → cmd.exe` activity.
- Multiple unrelated processes in broader parent-child searches.

### Confirmed

- The controlled commands were intentionally executed.
- `whoami.exe` execution was supported by process telemetry.
- `hostname.exe` was present in the `cmd.exe` command line.
- No malicious payload was introduced.

### Unknown

- Why a standalone `hostname.exe` event was not present in the queried dataset.
- Whether every child process generated by `cmd.exe` is consistently captured under the current telemetry configuration.

## Malicious Activity Assessment

The controlled process chain does not establish malicious activity.

No evidence was demonstrated for:

- Malware execution
- Persistence
- Credential access
- Privilege escalation
- Command-and-control
- Defense evasion
- Confirmed compromise

The existing `updater.exe → cmd.exe` activity was also not classified as malicious solely from the available process relationship.

