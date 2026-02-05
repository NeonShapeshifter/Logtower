import { Rule } from '@neonshapeshifter/logtower-engine';

export const SHELLS_RULES: Rule[] = [
  {
    "id": "SH_711_PYTHON_REVERSE",
    "title": "Python Reverse Shell Pattern",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059.006"],
    "detection": { "selection": { "process.image": "*python*.exe", "process.command_line": ["*-c*", "*import socket*", "*subprocess*"] } },
    "description": "Detects a Python reverse shell one-liner. Attackers use this to gain an interactive command shell on the victim machine by connecting back to their listener.",
    "response_steps": [
      "1. CONNECTION: Identify the destination IP and Port (C2).",
      "2. KILL: Terminate the python process.",
      "3. PARENT: Check what spawned this shell (Web server exploit? RCE?)."
    ]
  },
  {
    "id": "SH_712_PYTHON_PTY",
    "title": "Python PTY Spawn",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1059.006"],
    "detection": { "selection": { "process.command_line": ["*import pty*", "*pty.spawn*"] } },
    "description": "Detects Python spawning a PTY (Pseudo-Terminal). This is a common post-exploitation technique to upgrade a dumb shell (non-interactive) to a full TTY interactive shell.",
    "response_steps": [
      "1. CONTEXT: This almost always happens AFTER initial access.",
      "2. ISOLATE: The attacker has interactive control."
    ]
  },
  {
    "id": "SH_713_PERL_REVERSE",
    "title": "Perl Reverse Shell Pattern",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059.006"],
    "detection": { "selection": { "process.image": "*perl*.exe", "process.command_line": ["*-e*", "*use Socket*", "*connect*"] } },
    "description": "Detects a Perl reverse shell one-liner.",
    "response_steps": [
      "1. ISOLATE: Confirmed C2 channel.",
      "2. INVESTIGATE: Perl is rarely installed on Windows unless it's a dev machine or Strawberry Perl."
    ]
  },
  {
    "id": "SH_714_RUBY_REVERSE",
    "title": "Ruby Reverse Shell Pattern",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059.006"],
    "detection": { "selection": { "process.image": "*ruby*.exe", "process.command_line": ["*-e*", "*require 'socket'*", "*TCPSocket*"] } },
    "description": "Detects a Ruby reverse shell one-liner.",
    "response_steps": [
      "1. CHECK: Is this a legitimate Ruby application?",
      "2. NETWORK: Verify outbound connection."
    ]
  },
  {
    "id": "SH_715_LUA_REVERSE",
    "title": "Lua Reverse Shell Pattern",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059.006"],
    "detection": { "selection": { "process.image": "*lua*.exe", "process.command_line": ["*-e*", "*require('socket')*", "*connect*"] } },
    "description": "Detects a Lua reverse shell one-liner.",
    "response_steps": [
      "1. CONTEXT: Often used in game servers or embedded device exploits."
    ]
  },
  {
    "id": "SH_716_PHP_REVERSE",
    "title": "PHP Reverse Shell Pattern",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059.006"],
    "detection": { "selection": { "process.image": "*php*.exe", "process.command_line": ["*-r*", "*fsockopen*", "*exec*"] } },
    "description": "Detects a PHP reverse shell one-liner. Common payload for web application vulnerabilities (RCE).",
    "response_steps": [
      "1. WEB SERVER: If run by IIS/Apache, patch the vulnerability.",
      "2. ISOLATE: Full web server compromise."
    ]
  },
  {
    "id": "SH_717_NC_EXEC_SHELL",
    "title": "Netcat Execute Shell",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059"],
    "detection": { "selection": { "process.image": ["*nc.exe", "*nc64.exe"], "process.command_line": ["*-e*", "*cmd.exe*"] } },
    "description": "Detects Netcat (nc) spawning a command shell via '-e cmd.exe'. The classic reverse shell.",
    "response_steps": [
      "1. ISOLATE: Immediate threat.",
      "2. FILE: Locate the nc.exe binary (often renamed).",
      "3. BLOCK: Block the destination IP."
    ]
  },
  {
    "id": "SH_718_NCAT_EXEC_SHELL",
    "title": "Ncat Execute Shell",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059"],
    "detection": { "selection": { "process.image": "*ncat.exe", "process.command_line": ["*--exec*", "*cmd.exe*"] } },
    "description": "Detects Nmap's Ncat spawning a shell. Ncat supports SSL, making the traffic encrypted.",
    "response_steps": [
      "1. ENCRYPTION: Traffic will be encrypted (SSL), so IDS signatures might miss it.",
      "2. PROCESS: Kill the ncat process."
    ]
  },
  {
    "id": "SH_719_SOCAT_EXEC",
    "title": "Socat Exec Shell",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059"],
    "detection": { "selection": { "process.image": "*socat.exe", "process.command_line": ["*exec:*", "*cmd.exe*"] } },
    "description": "Detects Socat spawning a shell. Socat is a powerful networking tool used for relays and reverse shells.",
    "response_steps": [
      "1. CAPABILITIES: Socat can pivot traffic. Check for port forwarding arguments.",
      "2. ISOLATE: High confidence threat."
    ]
  },
  {
    "id": "SH_720_OPENSSL_SHELL",
    "title": "OpenSSL Reverse Shell",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059"],
    "detection": { "selection": { "process.image": "*openssl.exe", "process.command_line": ["*s_client*", "*-quiet*", "*connect*"] } },
    "description": "Detects OpenSSL used as a reverse shell client. Attackers pipe cmd.exe input/output through an openssl s_client connection.",
    "response_steps": [
      "1. ISOLATE: Encrypted C2 channel.",
      "2. PARENT: Check process hierarchy."
    ]
  },
  {
    "id": "SH_721_TELNET_CLIENT",
    "title": "Telnet Client Usage",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1095"],
    "detection": { "selection": { "process.image": "*telnet.exe" } },
    "description": "Detects usage of the legacy Telnet client. Data is sent in plaintext. Attackers use it for simple C2 or banner grabbing.",
    "response_steps": [
      "1. DESTINATION: Check the IP.",
      "2. SNIFF: Traffic is unencrypted, capture packets if possible."
    ]
  },
  {
    "id": "SH_722_SSH_CLIENT_EXEC",
    "title": "SSH Client Command Exec",
    "severity": "MEDIUM",
    "module": "LATERAL",
    "mitre": ["T1021.004"],
    "detection": { "selection": { "process.image": "*ssh.exe", "process.command_line": "*@*" } },
    "description": "Detects usage of Windows native OpenSSH client to connect to a remote host.",
    "response_steps": [
      "1. CONTEXT: Is this an admin workstation?",
      "2. TARGET: Identify the remote host (user@host)."
    ]
  },
  {
    "id": "SH_723_PLINK_EXEC",
    "title": "Plink Command Exec",
    "severity": "HIGH",
    "module": "LATERAL",
    "mitre": ["T1021.004"],
    "detection": { "selection": { "process.image": "*plink.exe", "process.command_line": ["*-pw*", "*-m*"] } },
    "description": "Detects Plink (Putty Link). Commonly used by attackers to create SSH tunnels (RDP over SSH) or execute remote commands non-interactively.",
    "response_steps": [
      "1. TUNNEL: Look for -R or -L arguments indicating port forwarding.",
      "2. KILL: Terminate the session."
    ]
  },
  {
    "id": "SH_724_PUTTY_CLI",
    "title": "Putty CLI Usage",
    "severity": "LOW",
    "module": "LATERAL",
    "mitre": ["T1021.004"],
    "detection": { "selection": { "process.image": "*putty.exe", "process.command_line": ["*-ssh*", "*-pw*"] } },
    "description": "Detects scriptable Putty usage. Less common for attackers than Plink, but possible.",
    "response_steps": [
      "1. VERIFY: User intent."
    ]
  },
  {
    "id": "SH_725_AWK_REVERSE",
    "title": "Awk Reverse Shell",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059"],
    "detection": { "selection": { "process.image": "*awk.exe", "process.command_line": ["*BEGIN*", "*Socket*"] } },
    "description": "Detects Awk reverse shell. Rare on Windows unless Unix utils are installed.",
    "response_steps": [
      "1. ISOLATE: Confirmed C2."
    ]
  },
  {
    "id": "SH_726_GAWK_REVERSE",
    "title": "Gawk Reverse Shell",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059"],
    "detection": { "selection": { "process.image": "*gawk.exe", "process.command_line": ["*BEGIN*", "*Socket*"] } },
    "description": "Detects Gawk (GNU Awk) reverse shell.",
    "response_steps": [
      "1. ISOLATE: Confirmed C2."
    ]
  },
  {
    "id": "SH_727_JAVA_REVERSE",
    "title": "Java Reverse Shell Class",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059"],
    "detection": { "selection": { "process.image": "*java.exe", "process.command_line": ["*Runtime*", "*exec*", "*cmd.exe*"] } },
    "description": "Detects Java executing cmd.exe via Runtime.exec. Typical of Java Deserialization exploits yielding a shell.",
    "response_steps": [
      "1. ISOLATE: Web server compromised.",
      "2. PATCH: Identify vulnerable Java app."
    ]
  },
  {
    "id": "SH_728_NODE_REVERSE",
    "title": "NodeJS Reverse Shell",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059"],
    "detection": { "selection": { "process.image": "*node.exe", "process.command_line": ["*-e*", "*child_process*", "*spawn*"] } },
    "description": "Detects NodeJS spawning a shell.",
    "response_steps": [
      "1. ISOLATE: Node app compromised.",
      "2. CODE: Review the JS payload."
    ]
  },
  {
    "id": "SH_729_DENO_REVERSE",
    "title": "Deno Reverse Shell",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059"],
    "detection": { "selection": { "process.image": "*deno.exe", "process.command_line": ["*run*", "*--allow-net*", "*subprocess*"] } },
    "description": "Detects Deno spawning a shell.",
    "response_steps": [
      "1. ISOLATE: Application compromise."
    ]
  },
  {
    "id": "SH_730_POWERSHELL_TCP_CLIENT",
    "title": "PowerShell TCP Client (Raw)",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059.001"],
    "detection": { "selection": { "process.command_line": ["*New-Object*", "*Net.Sockets.TcpClient*"] } },
    "description": "Detects raw usage of .NET TcpClient in PowerShell. Used for custom C2 protocols or raw socket reverse shells.",
    "response_steps": [
      "1. DESTINATION: Check IP and Port.",
      "2. SCRIPT: What script is instantiating this object?"
    ]
  },
  {
    "id": "SH_731_POWERSHELL_UDP_CLIENT",
    "title": "PowerShell UDP Client (Raw)",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059.001"],
    "detection": { "selection": { "process.command_line": ["*New-Object*", "*Net.Sockets.UdpClient*"] } },
    "description": "Detects usage of .NET UdpClient in PowerShell. Used for DNS tunneling or UDP-based C2.",
    "response_steps": [
      "1. TRAFFIC: Check for high volume of UDP packets.",
      "2. SCRIPT: Identify the source."
    ]
  },
  {
    "id": "SH_732_BASH_REVERSE",
    "title": "Bash Reverse Shell (WSL)",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059.004"],
    "detection": { "selection": { "process.image": "*bash.exe", "process.command_line": ["*-i*", "*&*", "*/dev/tcp/*"] } },
    "description": "Detects a classic Bash reverse shell (/dev/tcp) running via WSL (Windows Subsystem for Linux).",
    "response_steps": [
      "1. ISOLATE: C2 via WSL.",
      "2. WSL: Check installed WSL distros."
    ]
  },
  {
    "id": "SH_733_SH_REVERSE",
    "title": "Sh Reverse Shell (WSL)",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059.004"],
    "detection": { "selection": { "process.image": "*sh.exe", "process.command_line": ["*-i*", "*&*", "*/dev/tcp/*"] } },
    "description": "Detects Sh reverse shell via WSL.",
    "response_steps": [
      "1. ISOLATE: C2 via WSL."
    ]
  },
  {
    "id": "SH_734_ZSH_REVERSE",
    "title": "Zsh Reverse Shell (WSL)",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1059.004"],
    "detection": { "selection": { "process.image": "*zsh.exe", "process.command_line": ["*zsh/net/tcp*"] } },
    "description": "Detects Zsh reverse shell via WSL.",
    "response_steps": [
      "1. ISOLATE: C2 via WSL."
    ]
  },
  {
    "id": "SH_735_CHISEL_SERVER",
    "title": "Chisel Server Mode",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1572"],
    "detection": { "selection": { "process.command_line": ["*chisel*", "*server*", "*--reverse*"] } },
    "description": "Detects Chisel running in server mode. Chisel is a fast TCP/UDP tunnel over HTTP used for pivoting.",
    "response_steps": [
      "1. ISOLATE: Tunneling tool detected.",
      "2. NETWORK: Attackers are using this host to route traffic to others."
    ]
  },
  {
    "id": "SH_736_CHISEL_CLIENT_CONNECT",
    "title": "Chisel Client Connect",
    "severity": "CRITICAL",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1572"],
    "detection": { "selection": { "process.command_line": ["*chisel*", "*client*", "*R:*:*"] } },
    "description": "Detects Chisel client connecting to a server (Reverse Tunnel).",
    "response_steps": [
      "1. DESTINATION: This is the attacker's C2 IP.",
      "2. BLOCK: Block IP immediately."
    ]
  },
  {
    "id": "SH_737_GOST_PROXY",
    "title": "Gost Proxy Execution",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1090"],
    "detection": { "selection": { "process.image": "*gost.exe", "process.command_line": ["*-L*", "*-F*"] } },
    "description": "Detects Gost (GO Simple Tunnel). Multi-protocol proxy tool used for evasion.",
    "response_steps": [
      "1. ISOLATE: Proxy tool usage.",
      "2. CONFIG: Check arguments for forwarding rules."
    ]
  },
  {
    "id": "SH_738_YAGM_PROXY",
    "title": "Yagm Proxy Execution",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1090"],
    "detection": { "selection": { "process.image": "*yagm.exe" } },
    "description": "Detects Yet Another Go Mux (Yagm). Multiplexing proxy.",
    "response_steps": [
      "1. ISOLATE: Unknown proxy tool."
    ]
  },
  {
    "id": "SH_739_3PROXY_EXEC",
    "title": "3Proxy Execution",
    "severity": "HIGH",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1090"],
    "detection": { "selection": { "process.image": "*3proxy.exe" } },
    "description": "Detects 3Proxy tiny proxy server.",
    "response_steps": [
      "1. CHECK: Used for pivoting traffic."
    ]
  },
  {
    "id": "SH_740_STUNNEL_EXEC",
    "title": "Stunnel Execution",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1573.002"],
    "detection": { "selection": { "process.image": "*stunnel.exe" } },
    "description": "Detects Stunnel. Encapsulates TCP connections in SSL.",
    "response_steps": [
      "1. CONFIG: Check stunnel.conf.",
      "2. LEGITIMACY: Verify if authorized."
    ]
  },
  {
    "id": "SH_741_RSYNC_EXEC",
    "title": "Rsync Data Transfer",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1048"],
    "detection": { "selection": { "process.image": "*rsync.exe" } },
    "description": "Detects usage of Rsync on Windows.",
    "response_steps": [
      "1. DESTINATION: Where is data going?",
      "2. VOLUME: How much data was moved?"
    ]
  },
  {
    "id": "SH_742_SCP_EXEC",
    "title": "SCP Data Transfer",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1048"],
    "detection": { "selection": { "process.image": "*scp.exe" } },
    "description": "Detects usage of Secure Copy (SCP).",
    "response_steps": [
      "1. SOURCE/DEST: Mapping data movement."
    ]
  },
  {
    "id": "SH_743_SFTP_EXEC",
    "title": "SFTP Data Transfer",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1048"],
    "detection": { "selection": { "process.image": "*sftp.exe" } },
    "description": "Detects SFTP usage.",
    "response_steps": [
      "1. CHECK: Unauthorized data transfer."
    ]
  },
  {
    "id": "SH_744_FTP_SCRIPT",
    "title": "FTP Script Execution",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1048"],
    "detection": { "selection": { "process.image": "*ftp.exe", "process.command_line": ["*-s:*", "*-i*"] } },
    "description": "Detects FTP in script mode. Often used for automated exfiltration.",
    "response_steps": [
      "1. SCRIPT: Read the script file.",
      "2. IP: Identify FTP server."
    ]
  },
  {
    "id": "SH_745_TFTP_GET",
    "title": "TFTP Get File",
    "severity": "MEDIUM",
    "module": "COMMAND_AND_CONTROL",
    "mitre": ["T1105"],
    "detection": { "selection": { "process.image": "*tftp.exe", "process.command_line": ["*-i*", "*GET*"] } },
    "description": "Detects TFTP download. UDP-based, often allowed through firewalls.",
    "response_steps": [
      "1. FILE: What file was downloaded?"
    ]
  },
  {
    "id": "SH_746_TFTP_PUT",
    "title": "TFTP Put File",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1048"],
    "detection": { "selection": { "process.image": "*tftp.exe", "process.command_line": ["*-i*", "*PUT*"] } },
    "description": "Detects TFTP upload.",
    "response_steps": [
      "1. DATA: What was exfiltrated?"
    ]
  },
  {
    "id": "SH_747_CURL_UPLOAD",
    "title": "Curl Upload File",
    "severity": "HIGH",
    "module": "EXFILTRATION",
    "mitre": ["T1048"],
    "detection": { "selection": { "process.image": "*curl.exe", "process.command_line": ["*-T*", "*--upload-file*"] } },
    "description": "Detects Curl uploading a file via PUT.",
    "response_steps": [
      "1. URL: Destination server.",
      "2. FILE: Uploaded content."
    ]
  },
  {
    "id": "SH_748_CURL_POST",
    "title": "Curl POST Data",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1048"],
    "detection": { "selection": { "process.image": "*curl.exe", "process.command_line": ["*-d*", "*--data*"] } },
    "description": "Detects Curl sending data via POST.",
    "response_steps": [
      "1. DATA: Check data sent."
    ]
  },
  {
    "id": "SH_749_WGET_POST",
    "title": "Wget POST File",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1048"],
    "detection": { "selection": { "process.image": "*wget.exe", "process.command_line": ["*--post-file*"] } },
    "description": "Detects Wget posting a file.",
    "response_steps": [
      "1. DESTINATION: Exfiltration target."
    ]
  },
  {
    "id": "SH_750_CERTUTIL_POST",
    "title": "Certutil POST (Not Standard)",
    "severity": "HIGH",
    "module": "EXFILTRATION",
    "mitre": ["T1048"],
    "detection": { "selection": { "process.image": "*certutil.exe", "process.command_line": ["*-ping*", "*-config*"] } },
    "description": "Detects usage of Certutil -ping to send data in the URL params.",
    "response_steps": [
      "1. URL: Data is encoded in the URL path."
    ]
  },
  {
    "id": "SH_751_POWERSHELL_IWR_POST",
    "title": "PowerShell IWR POST",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1048"],
    "detection": { "selection": { "process.command_line": ["*Invoke-WebRequest*", "*-Method Post*"] } },
    "description": "Detects PowerShell posting data.",
    "response_steps": [
      "1. CHECK: Script context."
    ]
  },
  {
    "id": "SH_752_POWERSHELL_IRM_POST",
    "title": "PowerShell IRM POST",
    "severity": "MEDIUM",
    "module": "EXFILTRATION",
    "mitre": ["T1048"],
    "detection": { "selection": { "process.command_line": ["*Invoke-RestMethod*", "*-Method Post*"] } },
    "description": "Detects PowerShell posting data via RestMethod.",
    "response_steps": [
      "1. API: Endpoint analysis."
    ]
  },
  {
    "id": "SH_753_RUNDLL32_JAVASCRIPT",
    "title": "Rundll32 JavaScript Shell",
    "severity": "CRITICAL",
    "module": "EXECUTION",
    "mitre": ["T1059.007"],
    "detection": { "selection": { "process.command_line": ["*rundll32*", "*javascript:*", "*RunHTMLApplication*"] } },
    "description": "Detects Rundll32 executing JavaScript.",
    "response_steps": [
      "1. ISOLATE: Malicious script execution.",
      "2. DECODE: Extract script from command line."
    ]
  },
  {
    "id": "SH_754_MSHTA_VBSCRIPT",
    "title": "Mshta VBScript Shell",
    "severity": "CRITICAL",
    "module": "EXECUTION",
    "mitre": ["T1059.005"],
    "detection": { "selection": { "process.command_line": ["*mshta*", "*vbscript:*", "*execute*"] } },
    "description": "Detects Mshta executing VBScript inline.",
    "response_steps": [
      "1. ISOLATE: Malicious script execution."
    ]
  },
  {
    "id": "SH_755_MSHTA_JAVASCRIPT",
    "title": "Mshta JavaScript Shell",
    "severity": "CRITICAL",
    "module": "EXECUTION",
    "mitre": ["T1059.007"],
    "detection": { "selection": { "process.command_line": ["*mshta*", "*javascript:*", "*Run*"] } },
    "description": "Detects Mshta executing JavaScript inline.",
    "response_steps": [
      "1. ISOLATE: Malicious script execution."
    ]
  },
  {
    "id": "SH_756_REGASM_CODE",
    "title": "RegAsm Code Execution",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1218.009"],
    "detection": { "selection": { "process.image": "*regasm.exe", "process.command_line": ["*/U*", "*/nologo*"] } },
    "description": "Detects RegAsm executing code (AppLocker Bypass).",
    "response_steps": [
      "1. FILE: Identify payload DLL."
    ]
  },
  {
    "id": "SH_757_REGKSVCS_CODE",
    "title": "RegSvcs Code Execution",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1218.009"],
    "detection": { "selection": { "process.image": "*regsvcs.exe", "process.command_line": ["*/U*", "*/nologo*"] } },
    "description": "Detects RegSvcs executing code.",
    "response_steps": [
      "1. FILE: Identify payload DLL."
    ]
  },
  {
    "id": "SH_758_INSTALLUTIL_CODE",
    "title": "InstallUtil Code Execution",
    "severity": "HIGH",
    "module": "EXECUTION",
    "mitre": ["T1218.004"],
    "detection": { "selection": { "process.image": "*installutil.exe", "process.command_line": ["*/logfile=*", "*/U*"] } },
    "description": "Detects InstallUtil executing code.",
    "response_steps": [
      "1. FILE: Identify payload executable."
    ]
  },
  {
    "id": "SH_759_DFSVC_CODE",
    "title": "Dfsvc Code Execution",
    "severity": "MEDIUM",
    "module": "DEFENSE",
    "mitre": ["T1127"],
    "detection": { "selection": { "process.image": "*dfsvc.exe" } },
    "description": "Detects Dfsvc (ClickOnce) usage.",
    "response_steps": [
      "1. APP: Check application launched."
    ]
  },
  {
    "id": "SH_760_IEEXEC_CODE",
    "title": "IEExec Code Execution",
    "severity": "CRITICAL",
    "module": "DEFENSE",
    "mitre": ["T1127"],
    "detection": { "selection": { "process.image": "*ieexec.exe", "process.command_line": "*http:*" } },
    "description": "Detects IEExec executing remote code.",
    "response_steps": [
      "1. URL: Check remote source.",
      "2. ISOLATE: Confirmed remote execution."
    ]
  }
];