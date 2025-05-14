# Wireshark Threat Hunting – Key Queries for Detecting Network Anomalies

A curated list of Wireshark display filters useful for threat hunting and detecting suspicious or malicious network behavior.

---

## 🔍 FTP

* **FTP Login Successful**
  `ftp.response.code == 230`
  *Indicates successful login to an FTP server.*

* **FTP Command PASV (Passive Mode)**
  `ftp.request.command == "PASV"`
  *Requests passive mode, useful for detecting data exfiltration.*

* **FTP Command LIST (Directory Listing)**
  `ftp.request.command == "LIST"`
  *Used to retrieve file listings. May indicate probing.*

---

## 🌐 HTTP

* **HTTP GET Request**
  `http.request.method == "GET"`

* **HTTP POST Request**
  `http.request.method == "POST"`

* **HTTP 200 OK**
  `http.response.code == 200`

* **HTTP 404 Not Found**
  `http.response.code == 404`

* **HTTP Redirect (301/302)**
  `http.response.code == 301 or http.response.code == 302`

* **Suspicious HTTP POST Requests (Exfiltration)**
  `http.request.method == "POST" and http.content_length > 1000`

* **HTTP Response with Large Payload**
  `http.response.code == 200 and http.content_length > 5000`

* **HTTP Request to Suspicious Domain**
  `http.host == "suspicious.com"`

* **HTTP Content-Type: JSON**
  `http.content_type == "application/json"`

* **HTTP Basic Authentication**
  `http.authorization`

* **Suspicious User-Agent (e.g. sqlmap)**
  `http.user_agent contains "sqlmap"`

* **HTTP Response with Specific Cookie**
  `http.cookie contains "sessionid"`

* **Unencrypted HTTP on Port 443**
  `http and tcp.dstport == 443`

---

## 📡 DNS

* **Any DNS Traffic**
  `dns`

* **DNS Query for Specific Domain**
  `dns.qry.name == "example.com"`

* **Large Number of DNS Requests from Host**
  `dns and ip.src == <IP_ADDRESS>`

* **DNS Tunneling Detection**
  `dns.qry.name contains ".base64"`

* **DNS to Malicious Domain**
  `dns.qry.name == "malicious.com"`

* **Excessive NXDOMAIN Responses**
  `dns.flags.rcode == 3`

* **DNS Flood Detection (Many Responses)**
  `dns and dns.flags.response == 1`

---

## 🔐 TLS / SSL

* **All TLS/SSL Traffic**
  `tls`

* **TLS Handshake**
  `tls.handshake`

* **TLS ClientHello with Weak Cipher**
  `tls.handshake.ciphersuite == 0x0035`

* **Unusual TLS Handshake Patterns**
  `tls.handshake`
  *(Look for anomalies manually.)*

---

## 🧱 TCP & Connection Flags

* **TCP SYN (Connection Start)**
  `tcp.flags.syn == 1 and tcp.flags.ack == 0`

* **TCP FIN (Connection End)**
  `tcp.flags.fin == 1`

* **TCP Retransmissions**
  `tcp.analysis.retransmission`

* **TCP Window Size > 0**
  `tcp.window_size > 0`

* **SYN Flood Detection**
  `tcp.flags.syn == 1 and tcp.flags.ack == 0`
  *(Look for many SYNs with no ACKs.)*

* **Port Scanning Behavior**
  `tcp.flags.syn == 1 and tcp.dstport not in {80, 443, 22}`

* **Suspicious Ports (Non-standard)**
  `tcp.dstport not in {22, 80, 443, 53}`

---

## 📡 UDP / ICMP / Other Protocols

* **UDP Traffic**
  `udp`

* **ICMP Echo Request (Ping)**
  `icmp.type == 8`

* **ICMP Echo Reply**
  `icmp.type == 0`

* **ARP Requests**
  `arp.opcode == 1`

---

## 💻 Protocol-Specific

* **RDP Traffic (Remote Desktop)**
  `tcp.port == 3389`

* **RDP Session Hijacking or Unauthorized Access**
  `tcp.port == 3389` *(Investigate unusual IPs)*

* **SSH Brute Force Attempts**
  `ssh.auth.failed == 1`

* **SSH Login from New IP**
  `ssh and ip.src == <new_IP_ADDRESS>`

* **SMBv2 Traffic (Suspicious File Sharing)**
  `smb2`

* **SMTP HELO Command**
  `smtp.command == "HELO"`

* **Telnet Traffic**
  `telnet`

---

## ⚠️ Suspicious or Malicious Indicators

* **Malformed Packets**
  `frame.validation_failed == 1`

* **Traffic to/from Known Malicious IP**
  `ip.src == <Malware_IP> or ip.dst == <Malware_IP>`

* **Large Traffic from One Host (Possible DDoS)**
  `ip.src == <IP_ADDRESS> and ip.len > 1000`

---

> Replace `<IP_ADDRESS>`, `<new_IP_ADDRESS>`, or `<Malware_IP>` with actual values for your investigation.

---

## 📚 Credits

Compiled by threat hunters and security analysts to aid in real-time detection and forensic packet analysis.

---

You can copy this directly into your `README.md`, and GitHub will render it as a clean and organized document.

If you'd like, I can also create a GitHub-friendly `.md` file version for you to upload. Just let me know.
