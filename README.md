# Wireshark Threat Hunting – Key Queries for Detecting Network Anomalies

A curated list of Wireshark display filters useful for **threat hunting**, **network monitoring**, and **malware investigation**. Use these filters to detect suspicious or malicious activities across various protocols.

---

## 🔍 FTP (File Transfer Protocol)

* `ftp.response.code == 230`
  ✅ *Shows a successful FTP login, which could be used to check for unauthorized access.*

* `ftp.request.command == "PASV"`
  ✅ *Passive mode file transfers are often used in malware exfiltration or to evade firewalls.*

* `ftp.request.command == "LIST"`
  ✅ *Lists directory contents. Repeated usage may indicate directory snooping or probing.*

---

## 🌐 HTTP (Web Traffic)

* `http.request.method == "GET"`
  ✅ *Standard request for fetching web resources (pages, scripts, etc.).*

* `http.request.method == "POST"`
  ✅ *Used to send data (like forms or files) to a web server. Useful for detecting data exfiltration.*

* `http.response.code == 200`
  ✅ *Successful HTTP request. Can be used to verify connections.*

* `http.response.code == 404`
  ✅ *Page not found. Excessive 404s may indicate scanning.*

* `http.response.code == 301 or http.response.code == 302`
  ✅ *Redirects. Watch for unusual redirects to suspicious domains.*

* `http.request.method == "POST" and http.content_length > 1000`
  ✅ *Large POST requests may indicate exfiltration of sensitive data.*

* `http.response.code == 200 and http.content_length > 5000`
  ✅ *May show large file downloads that should be verified.*

* `http.host == "suspicious.com"`
  ✅ *Requests to a known malicious domain.*

* `http.content_type == "application/json"`
  ✅ *Indicates JSON API traffic. Can help detect command-and-control (C2) data.*

* `http.authorization`
  ✅ *Detects basic HTTP authentication headers, useful for credential harvesting detection.*

* `http.user_agent contains "sqlmap"`
  ✅ *Sqlmap is a common SQL injection tool. This filter detects its usage.*

* `http.cookie contains "sessionid"`
  ✅ *Used to track session hijacking attempts or investigate session fixation.*

* `http and tcp.dstport == 443`
  ⚠️ *Unencrypted HTTP traffic on port 443 (normally HTTPS). Could be suspicious or misconfigured.*

---

## 📡 DNS (Domain Name System)

* `dns`
  ✅ *All DNS traffic – useful for general monitoring.*

* `dns.qry.name == "example.com"`
  ✅ *Tracks queries to a specific domain.*

* `dns and ip.src == <IP_ADDRESS>`
  ✅ *Shows DNS traffic from a specific host – helps detect DNS tunneling.*

* `dns.qry.name contains ".base64"`
  ⚠️ *Possible DNS tunneling attempt using encoded data in subdomains.*

* `dns.qry.name == "malicious.com"`
  ✅ *Detects access to known bad domains – based on threat intel.*

* `dns.flags.rcode == 3`
  ⚠️ *NXDOMAIN response – the domain doesn't exist. High volume may indicate domain scanning or tunneling.*

* `dns and dns.flags.response == 1`
  ✅ *Filters for DNS response packets – can be used to measure flood or unusual answers.*

---

## 🔐 TLS / SSL (Secure Traffic)

* `tls`
  ✅ *All TLS/SSL encrypted traffic.*

* `tls.handshake`
  ✅ *TLS handshake data – useful to analyze client/server negotiation.*

* `tls.handshake.ciphersuite == 0x0035`
  ⚠️ *Weak cipher suite (e.g., TLS\_RSA\_WITH\_AES\_256\_CBC\_SHA) that should be flagged.*

* `tls.handshake`
  ⚠️ *Look for irregular or repeated handshakes – may indicate scanning or failed decryption.*

---

## 🧱 TCP & Connection Flags

* `tcp.flags.syn == 1 and tcp.flags.ack == 0`
  ✅ *SYN packet – beginning of a TCP handshake. Monitor for scans and DDoS.*

* `tcp.flags.fin == 1`
  ✅ *FIN flag indicates connection termination. Could help detect teardown patterns.*

* `tcp.analysis.retransmission`
  ⚠️ *Retransmitted packets. Excessive retransmits may signal congestion or evasion techniques.*

* `tcp.window_size > 0`
  ✅ *Useful for detecting active TCP flows or spotting zero-window anomalies.*

* `tcp.flags.syn == 1 and tcp.flags.ack == 0`
  ⚠️ *Multiple SYNs without ACKs = SYN flood attempt (DoS).*

* `tcp.flags.syn == 1 and tcp.dstport not in {80, 443, 22}`
  ⚠️ *TCP scan activity – scanning non-standard ports.*

* `tcp.dstport not in {22, 80, 443, 53}`
  ⚠️ *Non-standard ports – could indicate backdoors or unauthorized services.*

---

## 📡 UDP / ICMP / Other Protocols

* `udp`
  ✅ *All UDP traffic. Used for DNS, SNMP, VoIP, etc.*

* `icmp.type == 8`
  ✅ *ICMP Echo Request – typical ping.*

* `icmp.type == 0`
  ✅ *ICMP Echo Reply – response to ping.*

* `arp.opcode == 1`
  ✅ *ARP request – useful for local network scans or spoof detection.*

---

## 💻 Protocol-Specific Monitoring

* `tcp.port == 3389`
  ✅ *RDP traffic – monitor for remote access attempts.*

* `ssh.auth.failed == 1`
  ⚠️ *SSH brute-force detection (not always available unless Wireshark has that detail).*

* `ssh and ip.src == <new_IP_ADDRESS>`
  ✅ *Check for SSH logins from new or unauthorized IPs.*

* `smb2`
  ✅ *SMBv2 file sharing traffic – useful for lateral movement detection.*

* `smtp.command == "HELO"`
  ✅ *SMTP command – good for identifying email senders or relays.*

* `telnet`
  ⚠️ *Plaintext remote access. Should not be used in secure environments.*

---

## ⚠️ Suspicious or Malicious Indicators

* `frame.validation_failed == 1`
  ⚠️ *Malformed packets – could be crafted for attacks or tool errors.*

* `ip.src == <Malware_IP> or ip.dst == <Malware_IP>`
  ⚠️ *Known bad IP address – based on threat intelligence feeds.*

* `ip.src == <IP_ADDRESS> and ip.len > 1000`
  ⚠️ *Large packet sizes may signal data exfiltration, DDoS, or file transfers.*

---

> ⚙️ Replace `<IP_ADDRESS>`, `<Malware_IP>`, and other placeholders with actual values from your investigation.

---

## 📚 Credits

Compiled for SOC analysts, incident responders, and security enthusiasts to enhance **network visibility** and **incident response workflows** using Wireshark.
