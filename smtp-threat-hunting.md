# SMTP Email Traffic Analysis & Threat Hunting Using Splunk

---

##  Overview

This project focused on analyzing SMTP telemetry using Splunk and Zeek SMTP logs to investigate email-related network activity and identify unusual communication patterns.

Email infrastructure remains a common target for attackers and a key data source for SOC analysts performing investigations involving phishing, malware delivery, and unauthorized communications.

---

##  Objective

To analyze SMTP traffic, identify active mail systems, and investigate email communication patterns through threat hunting workflows.

---

##  Lab Setup

- **Log Source:** Zeek (`smtp.log`)
- **SIEM:** Splunk
- **Environment:** Virtual Lab (Kali Linux + VirtualBox)

---

##  Dataset

The SMTP logs contained:

- Source IP addresses
- Destination IP addresses
- Mail domains
- SMTP communication activity
- Server responses
- Network metadata

---

##  Detection Methodology

### 1. Email Domain Analysis

```spl
index=main sourcetype=zeek_smtp
| rex field=_raw "(?<ts>\d+\.\d+)\s+(?<uid>\S+)\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)\s+(?<src_port>\d+)\s+(?<dest_ip>\d+\.\d+\.\d+\.\d+)\s+(?<dest_port>\d+)\s+\d+\s+(?<mail_domain>\S+)"
| stats count by mail_domain
| sort - count
| head 20
```

### 2. SMTP Source Host Analysis

```spl
index=main sourcetype=zeek_smtp
| stats count by src_ip
| sort - count
| head 10
```

### 3. SMTP Destination Analysis

```spl
index=main sourcetype=zeek_smtp
| stats count by dest_ip
| sort - count
| head 10
```

---

##  Analysis & Findings

### Top Mail Domains

| Domain | Count |
|----------|--------:|
| example.com | 44 |
| example.org | 35 |
| nmap.scanme.org | 30 |
| nessus | 11 |
| mail.nessus.org | 10 |

### Top SMTP Source Hosts

| Source IP | Connections |
|------------|-----------:|
| 192.168.202.110 | 111 |
| 192.168.204.45 | 29 |
| 192.168.202.79 | 17 |
| 192.168.202.108 | 11 |
| 192.168.202.138 | 11 |

### Top SMTP Destinations

| Destination IP | Connections |
|----------------|-----------:|
| 192.168.22.102 | 24 |
| 192.168.229.251 | 19 |
| 192.168.21.102 | 18 |
| 192.168.22.203 | 16 |
| 192.168.22.202 | 15 |

---

##  SOC Insight

SMTP telemetry provides visibility into email infrastructure and communication behavior across a network.

Threat hunters frequently use SMTP logs to investigate:

- phishing activity
- suspicious email delivery
- malware distribution attempts
- unauthorized mail servers
- unusual communication patterns

During this investigation, several mail domains and high-volume SMTP hosts were identified and analyzed for abnormal activity.

---

##  Key Takeaway

Email-related telemetry remains an important data source for SOC analysts.

Monitoring SMTP traffic helps analysts understand communication patterns, identify anomalies, and support investigations involving phishing and email-based threats.

---

##  Next Steps

- Correlate SMTP traffic with DNS activity
- Investigate mail server relationships
- Create SMTP monitoring dashboards
- Develop email anomaly detection workflows
- Expand email threat hunting capabilities

---

##  Sample Output

Add screenshots:

```markdown
![Top Email Domains](top-email-domains.png)

![Top SMTP Source Hosts](top-smtp-source-hosts.png)

![Top SMTP Destinations](top-smtp-destinations.png)
```

---

##  Skills Demonstrated

- Splunk SPL
- SMTP Analysis
- Threat Hunting
- Detection Engineering
- Email Security Monitoring
- Network Traffic Analysis
- SIEM Operations
- Log Analysis
- Zeek Log Analysis
- SOC Operations
