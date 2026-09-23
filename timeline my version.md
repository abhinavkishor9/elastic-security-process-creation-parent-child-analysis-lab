# Timeline

| Time | Activity | Process | Parent | User | Evidence / Notes |
|---|---|---|---|---|---|
| 15:57:55.260 | Controlled command-shell execution | `cmd.exe` | `pwsh.exe` | `Dell` | `/c whoami.exe`, PID `21172`, parent PID `36120` |
| 15:57:55.296 | Controlled child execution | `whoami.exe` | `cmd.exe` | `Dell` | Separate `whoami.exe` process telemetry observed |
| 15:58:06.140 | Controlled command-shell execution | `cmd.exe` | `pwsh.exe` | `Dell` | `/c hostname.exe`, PID `13388`, parent PID `36120` |
| 15:58:53.620 | Additional `whoami.exe` activity | `whoami.exe` | Validate from telemetry | `Dell` | Additional endpoint event observed |
| 16:03:54.393 | Existing endpoint activity | `cmd.exe` | `updater.exe` | `SYSTEM` | McAfee WebAdvisor-related command line |
| 16:03:54.435 | Existing endpoint activity | `cmd.exe` | `updater.exe` | `SYSTEM` | Additional updater-related command line |

