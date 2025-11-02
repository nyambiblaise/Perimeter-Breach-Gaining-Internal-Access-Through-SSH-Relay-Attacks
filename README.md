# Perimeter-Breach-Gaining-Internal-Access-Through-SSH-Relay-Attacks
From edge to internal network in one move, this red team exercise shows how sshuttle can turn compromised credentials into full internal network access. We successfully pivoted to enumerate Windows Server 2016 systems; a stark reminder to enforce MFA, restrict SSH access, and monitor for lateral movement.

### Executive summary

This lab confirmed that an external attacker with compromised SSH credentials could pivot through the edge router to access an internal `10.1.16.0/24` subnet. Using `sshuttle`, TCP traffic was successfully relayed to internal hosts, enabling service discovery and host enumeration. The MS server at `10.1.16.2` was confirmed reachable over TCP and identified as Windows Server 2016 via SMB enumeration. The risk is assessed as **Medium-High**: with credential reuse and insufficient network segmentation, attackers can bypass perimeter filtering to enumerate and potentially exploit internal services.

### Scope and rules of engagement

- **In-Scope Networks:**
    - Attacker PC (Kali): `203.0.113.66`
    - Edge Subnet: `203.0.113.0/24`
    - Internal Subnet: `10.1.16.0/24`
    - Primary Target: MS Server `10.1.16.2`
- **Allowed Techniques:**
    - Network scanning, SSH-based relaying/pivoting, service enumeration over TCP.
    - No destructive actions, credential spraying, or privilege escalation on production systems.
- **Out of Scope:**
    - Denial of service, data exfiltration, privilege escalation on domain controllers.
- **Credentials:**
    - Previously obtained SSH credentials for the edge router were used. Find exploit here (https://github.com/nyambiblaise/Domain-Controller-DC-Exploitation-with-Metasploit-Impacket)
<img width="806" height="615" alt="image" src="https://github.com/user-attachments/assets/e7fdf449-fc50-4d68-bedc-e0c341341e95" />



### Timeline and actions performed

1. **Initial Reconnaissance**

We identified the Kali PC and scanned the local subnet to discover the edge router and other live hosts..

![image.png](attachment:626a58be-44ce-445f-aca3-5172639a03de:image.png)

![image.png](attachment:9c111548-0d42-4514-a728-e41c5bca06bc:image.png)

1. **Edge Router Service Discovery**
- Baseline Nmap reconnaissance confirmed the edge router (`203.0.113.1`) was accessible with SSH exposed.
- Services detected: SSH (22/tcp), SMTP (25/tcp), HTTP (80/tcp).
<img width="1217" height="398" alt="image" src="https://github.com/user-attachments/assets/97b8bca6-06e5-49a2-9027-d5df108f916b" />
<img width="1130" height="287" alt="image" src="https://github.com/user-attachments/assets/4c1a5a44-5d7f-4200-8b28-7ecba25bdc5e" />


As mentioned in the scope, we had previously exploited this server, so we’ll be skipping this part. you can find the exploit here (https://github.com/nyambiblaise/Domain-Controller-DC-Exploitation-with-Metasploit-Impacket)

Our quick scan on the edge router confirms that we can interact with it and that it hosts the SSH service.

1. **Direct Access Attempt to Internal Host**

• Attempted to ping `10.1.16.2` : all packets were blocked, confirming perimeter filtering, ICMP and initial TCP attempts failed.

<img width="1064" height="283" alt="image" src="https://github.com/user-attachments/assets/9ee47f98-261c-4e28-84a9-85492930e10f" />


1. **SSH Relay Setup with sshuttle**
- Used `sshuttle` with valid credentials to establish a TCP relay through the edge router (203.0.113.1) to the internal subnet `10.1.16.0/24`.
- Relay successfully established, enabling TCP-based communication to internal hosts.
- Since the ssh server is on a different subnet, we cannot directly access it, to do this, we need to route through a jump host or use another approach since trying to login to the ssh works..

<img width="1045" height="145" alt="image" src="https://github.com/user-attachments/assets/90489963-c29a-4cc0-9565-394f477a0b52" />

<img width="1538" height="605" alt="image" src="https://github.com/user-attachments/assets/fa8a3e35-542e-4359-9d24-c08295dd3356" />

We can see that the relay is now connected to the edge.

1. **Relay Validation**

• ICMP remained blocked, but TCP-based access (e.g., HTTP) to `10.1.16.2` was successful via `curl`.

<img width="1064" height="283" alt="image" src="https://github.com/user-attachments/assets/2855fa29-76d5-4903-ad46-ad1002770626" />


This failure is normal because SSHuttle relays TCP and not ICMP traffic. So for this, we try to access the MS via TCP using the web browser, netcat or curl which effectively confirms that our relay is successful and we are now within the subnet.

`curl http:// 10.1.16.2`

<img width="1261" height="299" alt="image" src="https://github.com/user-attachments/assets/a91d7a06-0e3b-4d81-95c4-5621e705f21b" />
<img width="1252" height="553" alt="image" src="https://github.com/user-attachments/assets/993f43d6-de6e-420a-a9ff-829ba4b32a7d" />


1. **Service Enumeration via Relay**
- Conducted TCP connect scan and SMB OS discovery against `10.1.16.2`.
- Identified the host as **Windows Server 2016 Standard** with NetBIOS name `MS10` and domain `ad.structurality.com`.
- Since sshuttle relays TCP traffic, we now try to scan and discover info about our MS target, so no need for SYN scan. We will use TCP connect scan (`-sT)`

`nmap -sT -Pn --script=smb-os-discovery -p 445 10.1.16.2` 

This confirms that we’ve got our target on site and it is running a Windows Server 2016

<img width="1213" height="506" alt="image" src="https://github.com/user-attachments/assets/b3f1cdac-04da-4711-9c75-5d126c72fabc" />


Recall, despite connected via a relay, pinging the edge PC from kali will still fail. Everything needs to be done from the relay.

<img width="1326" height="852" alt="image" src="https://github.com/user-attachments/assets/6c104fc4-b93b-4157-96fb-0abb667cbf7a" />


1. **Internal Subnet Scanning**
- Performed a broad TCP connect scan across `10.1.16.0/24` to enumerate additional hosts and services.
- Multiple internal systems and open ports were identified through the relay.

Now that we are inside the edge network and have gained access to router, we can perform fast scans across the subnet 10.1.16.0/24 to enumerate additional live hosts and services through the relay, pivot and identify other systems.

We can now scan for other systems within the internal subnet using `nmap -sT -Pn -F 10.1.16.0/24`

Performing an nmap scan and sshuttle is capturing it and this confirms that we have effectively connected to the edge and can enumerate other nodes alongside the services they are running.

<img width="852" height="321" alt="image" src="https://github.com/user-attachments/assets/2639e5e5-cf83-4f08-8957-98500478cb16" />


<img width="852" height="372" alt="image" src="https://github.com/user-attachments/assets/121d5b6f-5cef-4bcf-ab5c-f3a2e3fe38dc" />


## Findings

### **1. SSH Accessible on Edge Router from External Network**

- **Severity:** Medium
- **Description:** The edge router exposes SSH to the external subnet and accepted user authentication, enabling relay setup.
- **Evidence:** Nmap service detection confirmed open `tcp/22` on `203.0.113.1`.

### **2. Pivot Feasible via sshuttle to Internal Subnet**

- **Severity:** High
- **Description:** With valid SSH credentials, an attacker can route TCP traffic to `10.1.16.0/24`, bypassing perimeter controls and gaining internal visibility.
- **Evidence:** Successful `curl` and TCP scans to `10.1.16.2` after relay establishment; `sshuttle` logs show forwarded connections.

### **3. MS Server Enumerated Over SMB via Relay**

- **Severity:** Medium
- **Description:** SMB was reachable, and the OS was identified as Windows Server 2016 via `smb-os-discovery` over the relay.
- **Evidence:** Nmap script results provided OS, hostname, and domain details.

### Impact

- **Bypass of Network Segmentation:** Perimeter controls were circumvented using exposed SSH and credential reuse.
- **Internal Asset Exposure:** Attackers can enumerate services and versions, increasing the risk of targeted exploitation.
- **Lateral Movement Risk:** The relay serves as a stepping stone to additional hosts within the internal subnet, expanding the attack surface.

### Evidence (artifacts)

- Edge router service detection scans
- Pre-relay connectivity failures (ICMP and SMB)
- `sshuttle` relay configuration and syslog logs
- HTTP reachability to `10.1.16.2` via `curl`
- Nmap SMB OS discovery and subnet scan results

### Recommendations

- **Restrict SSH Exposure on Edge Devices:**
    - Limit source IPs via allow lists or VPN-only access.
    - Disable password authentication and enforce MFA or key-based auth.
- **Rotate and Harden Credentials:**
    - Enforce strong, unique passwords and regularly rotate credentials.
- **Strengthen Network Segmentation and Egress Filtering:**
    - Implement host and router ACLs to prevent SSH-based relaying to internal subnets.
    - Monitor for atypical SSH port forwarding and tunneling patterns.
- **Enhance Monitoring and Alerting:**
    - Alert on anomalous SSH sessions, internal scanning from management planes, and unusual TCP relay behavior.
- **Reduce SMB Attack Surface:**
    - Restrict SMB to necessary hosts, enforce SMB signing, and ensure Windows servers are patched.

### Importance to organizations

- **Prevents Silent Perimeter Bypass:** SSH relays can transform a single exposed service into broad internal access.
- **Limits Credential Compromise Impact:** Proper hardening and segmentation prevent stolen credentials from leading to full subnet visibility.
- **Improves Detection Capability:** Monitoring SSH tunneling and internal scanning accelerates threat containment.
- **Supports Compliance:** Controls around remote access and internal service exposure align with common security frameworks.

## **Tools Used**

The following tools were utilized during this engagement to conduct reconnaissance, establish persistence, and enumerate internal services:

### **Primary Tools:**

- **Kali Linux** - Penetration testing distribution used as the attacker platform - https://www.kali.org/docs/
- **Nmap** - Network discovery and service enumeration - https://nmap.org/docs.html
- **sshuttle** - SSH-based VPN relay for TCP traffic pivoting - https://github.com/sshuttle/sshuttle
- **sshpass** - SSH password authentication automation
- **cURL** - HTTP service interaction and validation

### **Supporting Tools:**

- **ifconfig** - Network interface configuration verification
- **ping** - Basic ICMP connectivity testing
- **netcat** - TCP connectivity validation
- **SMB OS Discovery Script** - Nmap script for Windows/SMB fingerprinting - https://nmap.org/nsedoc/scripts/smb-os-discovery.html
### Conclusion

This engagement demonstrated that with valid SSH access to the edge router, an attacker can relay TCP traffic to internal systems and enumerate critical services such as SMB on a Windows server. Addressing SSH exposure, enforcing strong authentication, and strengthening segmentation and monitoring will significantly reduce the likelihood and impact of relay-based lateral movement.
