# 🧠 Overview
This lab simulates a misconfigured MSSQL server accessible over the network, allowing attackers to :

- 🟢 Gain initial access
- 🛠 Execute OS-level commands
- 📦 Drop tools on target
- 📡 Set up a reverse shell 
- 🔐 Obtain elevated access
- 🧾 Retrieve flags.

## 🧭 MITRE ATT&CK Mapping
- 🛂 Initial Access
    - [T1078] Valid Accounts
- 🖥️ Execution
    - [T1059.001] Command and Scripting Interpreter: PowerShell
- 🔼 Privilege Escalation
    - [T1003.001] OS Credential Dumping: Local Credential Dumping
    - [T1050] New Service 
- 🔑 Credential Access
    - [T1552.001] Unsecured Credentials: Credentials In Files
- 🔍 Discovery
    - [T1087.001] Account Discovery: Local Account
    - [T1069.001] Permission Groups Discovery: Local Groups
- 📥 Collection
    - [T1005] Data from Local System
- 🕹️ Command and Control
    - [T1105] Ingress Tool Transfer
    - [T1059.003] Command and Scripting Interpreter: Windows Command Shell
    - [T1071.001] Application Layer Protocol: Web Protocols
- 📤 Exfiltration
    - [T1041] Exfiltration Over C2 Channel


### 🧭 Step-by-Step Walkthrough

#### 🔍 Port Scanning

- Used nmap to determine open ports on mssql server
- Determined port 1433/tcp is open, indicating an exposed MSSQL service

![Port Scan](./screenshots/port%20scanning.png)

#### 📁 SMB Enumeration

- Enumerated network shares on the target
- The ones with $ necessitate elevated privileges; backups folder does not!

![Network Share Enumeration](./screenshots/SMB%20enumeration.png)

#### 🔓 Network Share Access and Enumeration | Credential Access

- Via smbclient, connected to the `backups` share folder and enumerated it
- Discovered a configuration file, prod.dtsconfig
- Displayed the contents of cfg file, which included plaintext credentials for user "ARCHETYPE"

![backups share enumeration](./screenshots/network%20share%20access.png)
![Configuration File Retrieval](./screenshots/configuration%20file%20retrieval.png)
![Credential Access](./screenshots/credential%20access.png)


#### 🛂 Initial Access + 🔍 Discovery + 🧨Command Execution

- Logged into MSSQL using `mssqlclient.py` from Impacket with creds
- Discovered sql_svc has sysadmin role
- Enabled xp_cmdshell via EXEC sp_configure

![Initial Access](./screenshots/initial%20access.png)
![User Account Enumeration](./screenshots/user%20account%20enumeration.png)
![Determine User Access Level](./screenshots/determine%20user%20access%20level%20-%20discovery.png)
![Enable xp_cmdshell](./screenshots/enable%20xp_cmdshell.png)

#### 🚚 Tool Ingress

- Hosted nc64.exe with python3 -m http.server
- Downloaded it to target using PowerShell

![HTTP Server Creation](./screenshots/http%20server%20creation.png)
![Ingress Tool Transfer](./screenshots/ingress%20tool%20transfer.png)

#### 🕹️ Reverse Shell

- Set up listener with netcat
- Executed netcat on the target

![Start Netcat on C2](./screenshots/start%20netcat%20on%20C2.png)
![Netcat Execution on Target](./screenshots/netcat%20execution%20on%20target.png)

#### 🔑 Privilege Escalation

Found admin credentials in powershell's command history, ConsoleHost_history.txt

![Admin Credential Access](./screenshots/admin%20credential%20access.png)

#### 🏁 User Flag

- Retrieved user flag

![User Flag](./screenshots/user%20flag.png)

#### 👑 Administrator Access

- Used `psexec.py` from Impacket with to remotely authenticate via admin creds
- Retrieved root flag

![Remote Access via Psexec](./screenshots/remote%20access%20via%20psexec.png)  
![Admin Flag](./screenshots/admin%20flag.png)


#### 🔍 Investigation (Blue Team)

**1. Initial Recon / Port Scanning**    
**📌Attack Step:** nmap scan of open ports  
<br>
   **🛡️Detection:**  
           - <strong> IDS/IPS </strong> alerts for port scanning (Snort, Suricata)  
           - <strong> Firewall </strong> logs (multiple TCP SYNs from a single source). check if connection attempts were blocked or allowed  
           - **EDR** (i.e Crowdstrike) if nmap port scans are executed locally  
<br>
    **🔎Investigation:**  
           - Look for a **single source IP** making many connection attempts to different ports on the same host (vertical scan) or **the same port being scanned across many IPs** (horizontal scan)  
           - Pay attention to timing — scans often happen in **bursts within seconds**, which is a strong indicator of automation  
           - Review **Sysmon Event ID 3** for outbound scan behavior (if from an internal host)  
           - On the firewall, **check if connection attempts were blocked or allowed**  
<br>

**2. SMB Enumeration and File Exfiltration**   
**📌Attack Step:** Accessing an open SMB share (\\target\backups), pulling prod.dtsconfig  
<br>
   **🛡️Detection:**  
           - Event ID 5140: “A network share object was accessed." A user (or process) accessed a share (e.g., \\host\backups), not necessarily a specific file.   
           - Event ID 5145: “A network share object was checked to see whether client can access.”  This is file-level access, showing what file/folder was requested and with what access rights (read, write, etc.)  
           - SMB logon activity (4624 Type 3 from attacker IP)  
<br>
   **🔎Investigation:**  
           - Correlate SMB activity with logon activity and build a timeline. When did the activity start? which account was used? Were there any failed logons? which source IPs were involved? Which files/folders were accessed successfully?  
          - Unexpected logons to admin shares like `ADMIN$, C$`  
          - SMB access without corresponding interactive logon  
          - A single IP accessing multiple machines (lateral movement pattern)  
<br>

**3. Credential Access**  
**📌Attack Step:** Extracting creds in plaintext from prod.dtsconfig  
<br>
    **🛡️Detection:**  
          -  EDRs can detect this activity via event correlation (i.e. file accessed, credential reuse, enabling xp_cmdshell, downloading netcat, etc)  
          -  If deployed, file integrity monitoring can utilized to detect access to critical files  
          -  SIEM alerts can set up to detect access to files with extensions of .cfg/.configuration           
<br>
    **🔎Investigation:**  
          - Check Windows Security Logs (Event ID 4663) for file access events if auditing is enabled  
          - check Sysmon Event ID 1 to see command-line log and determine if the attacker viewed files via via `type`, `cat`, or `more`  
<br>
**4. MSSQL Login (Initial Access):**  
**📌Attack Step:** Logging in to MSSQL with `sql_svc` account using `mssqlclient.py`  
<br>
    **🛡️Detection:**  
           -  Enable MSSQL audit logs to record successful logons, permission changes, and executed commands  
           -  Sysmon event ID 3 to detect inbound and outbound traffic to port 1433 (MSSQL port) and connections from a non-domain joined  
           -  If the source IP is not one of those trusted machines (jump box)  
<br>
    **🔎Investigation:**  
           - Determine a baseline: what systems usually authenticate using `sql_svc`?   
           - Were there any failed login attempts before the successful logon (brute forcing sign)?  
           - Was this logon from a suspicious host?  
           - What activities transpired post logon? Was "xp_cmdshell" enabled to executed commands? Were any suspicious queries or commands executed?  
<br>
**5. Command Execution via xp_cmdshell:**  
**📌Attack Step:**  Enabling xp_cmdshell, then using it to run PowerShell and install netcat.  
<br>
 **🛡️Detection:**  
    - **Event ID 4688 (new process creation)**: Execution of powershell. exe, cmd.exe, or nc64.exe   
    - Review audit logs (MSSql logs) if xp_cmdshell is enabled  
    - Sysmon 1 (process creation) and sysmon event ID 11 (file creation)  
<br>
 **🔎Investigation:**  
    - Hunt for `xp_cmdshell` use   
    - hunt for powershell use and investigate child processes (i.e nc64.exe)    
    - Look for `cmd.exe` or `powershell.exe` execution from unusual parent processes    
<br>
**6. Tool Ingress: NetCat**  
**📌Attack Step:** Downloading nc64.exe via PowerShell from attacker HTTP server  
<br>
  **🛡️Detection:**  
    - Sysmon 3: Network connetions from target to attacker IP over port 80  
    - Sysmon 11: file creation events (nc64.exe drop)  
<br>
  **🔎Investigation:**  
    - Trace outbound HTTP requests to suspicious hosts  
    - look for unknown binaries being dropped   
<br>
**7. Reverse Shell Established:**  
**📌Attack Step:** Connecting back to the attacker's listener via nc64.exe  
<br>
  **🛡️Detection:**  
    - Sysmon 3: Outbound connection to uncommon IP  
    - Firewall logs: outbound connections to port 443 and uncommon IP  
    - Process tree: cmd.exe spawned from an unusual parent process and talking to C2/external IP  
<br>
  **🔎Investigation:**   
    - Look for long-running cmd.exe processes  
    - Investigate command line arguments  
<br>
**8. Privilege Escalation | Administrator Access**    
**📌Attack Step:** Reading PowerShell history file to extract administrator password  
<br>
  **🛡️Detection:**  
    - EDR tools, such as CrowdStrike will catch read actions  
    - **Detecting read access for history files is difficult because it is using a LOLBIN (powershell) and is considered normal behavior**  
<br>
  **🔎Investigation:**  
    - Look for unusual access and correlate with other events to detect nefarious activity  
<br>
**9. Objective Completed**  
**📌Attack Step:** Reading user.txt and root.txt    
<br>
  **🛡️Detection:**
    - Contextual correlation/detection    
<br>  
  **🔎Investigation:**
    - Contextual correlation: Correlate with time of psexec session
