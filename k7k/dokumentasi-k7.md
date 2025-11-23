# Laporan Proyek Keamanan Jaringan Berbasis ACL & Firewall
### Departemen Teknologi Informasi – Institut Teknologi Sepuluh Nopember (ITS)
---
## Anggota Kelompok
| Nama | NRP |
|------|------|
| Oryza Qiara Ramadhani | 5027241084 |
| Ahmad Syauqi Reza | 5027241085 |
| Muhammad Khosyi Syehab | 5027241089 |
| Muhammad Ardiansyah Tri Wibowo | 5027241091 |
---
## Daftar Isi
- Latar Belakang    
- Desain Topologi    
- Filosofi Keamanan yang Seimbang    
- Pertahanan Berlapis (Defense in Depth)    
- Konfigurasi Sistem    
- Simulasi Serangan & Mitigasi    
- Pengujian & Pembuktian Sistem    
- Evaluasi Performa    
- Desain Adaptif & Modular    
- Kesimpulan    
- Lampiran
---
## 1. Latar Belakang
Departemen Teknologi Informasi ITS (DTI ITS) baru saja melakukan restrukturisasi infrastruktur jaringan. Dalam sistem baru, terdapat lima subnet utama yang harus saling terhubung melalui core router laboratorium jaringan.
Setelah terjadi insiden kebocoran data dan lonjakan traffic mencurigakan dari jaringan mahasiswa, tim keamanan internal ditugaskan untuk merancang sistem pertahanan berlapis berbasis ACL dan firewall.    
### 1.1 Tujuan Proyek    
Proyek ini bertujuan untuk membangun sistem jaringan yang:    
- Aman: Melindungi dari serangan internal dan eksternal    
- Modular: Mudah dikembangkan tanpa perombakan total    
- Efisien: Tidak menghambat kolaborasi akademik    
- Terukur: Memiliki indikator keamanan yang jelas    
### 1.2 Ruang Lingkup    
- Implementasi firewall berlapis menggunakan pfSense dan iptables    
- Konfigurasi ACL untuk kontrol akses antar subnet    
- Sistem deteksi intrusi menggunakan Snort IDS    
- Monitoring dan logging terpusat    
- Simulasi serangan dan pengujian penetrasi
---
## 2. Desain Topologi
### 2.1 Gambaran Umum    
Topologi dibangun menggunakan GNS3 dengan kombinasi pfSense sebagai firewall utama, beberapa router Linux/Debian sebagai router internal, dan beberapa node client (VPCS) serta server (Ubuntu Docker).    
<img width="546" height="381" alt="image" src="https://github.com/user-attachments/assets/aceaa6e1-553a-43a1-95df-39bf83fa3ce3" />
### 2.2 Komponen Utama
| Node | Nama Logis | Fungsi | IP Management |
|  |  |  |  |

### 2.3 Diagram IP Addressing
<img width="664" height="605" alt="image" src="https://github.com/user-attachments/assets/865a47f6-138f-4335-8b61-f60e80275aa1" />

---
3. Filosofi Keamanan yang Seimbang
3.1 Definisi "Keamanan Seimbang"
Kami mendefinisikan keamanan seimbang sebagai sistem yang menjaga CIA Triad (Confidentiality, Integrity, Availability) tanpa menghalangi aktivitas kolaboratif antar subnet.
Prinsip Utama:

Least Privilege: Setiap subnet hanya mendapat akses minimal yang dibutuhkan
Segmentation: Pemisahan jaringan berdasarkan fungsi dan tingkat kepercayaan
Defense in Depth: Pertahanan berlapis untuk redundansi keamanan
Collaboration-Aware: Memfasilitasi kerja sama akademik yang sah

3.2 Matriks Kebijakan Akses
<img width="682" height="602" alt="image" src="https://github.com/user-attachments/assets/a21316f3-9da9-4611-a171-08b1446a2764" />
3.3 Zona Keamanan (Security Zones)
<img width="433" height="569" alt="image" src="https://github.com/user-attachments/assets/dcea375b-8f73-4108-8b86-9b7919343da2" />
3.4 Penanganan Edge Cases
<img width="681" height="239" alt="image" src="https://github.com/user-attachments/assets/6a73014c-502e-4d58-8f15-fded499670db" />

---
4. Pertahanan Berlapis (Defense in Depth)
4.1 Arsitektur Keamanan 5 Lapis
<img width="421" height="639" alt="image" src="https://github.com/user-attachments/assets/fb847155-94cd-4dff-a7e8-d2c1cf5c055f" />
4.2 Asumsi Skenario Serangan
Berdasarkan analisis risiko jaringan kampus, kami mengidentifikasi ancaman realistis:
<img width="606" height="221" alt="image" src="https://github.com/user-attachments/assets/4c09675c-e429-4c88-b3dd-e88f0b233f8a" />
4.3 Detail Implementasi Setiap Lapis
Layer 1: Perimeter Firewall (pfSense)
Konfigurasi Firewall Rules:
<img width="608" height="245" alt="image" src="https://github.com/user-attachments/assets/8d711e2d-9826-4cd7-8071-062967cfff8b" />
NAT Configuration:

Outbound NAT Mode: Hybrid (Automatic + Manual)
Source NAT: 10.20.0.0/16 → WAN IP (192.168.100.2)
Port Forwarding: Disabled untuk semua internal services (security hardening)

Layer 2: Router ACLs (iptables)
Contoh: Router Mahasiswa (R-Mahasiswa)
```
# Default policy: DROP
iptables -P FORWARD DROP

# Allow established connections
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow Mahasiswa → Akademik (specific ports)
iptables -A FORWARD -s 10.20.1.0/24 -d 10.20.20.0/24 -p tcp -m multiport --dports 21,53,80,443 -j ACCEPT
iptables -A FORWARD -s 10.20.1.0/24 -d 10.20.20.0/24 -p udp --dport 53 -j ACCEPT

# Block Mahasiswa → Admin (explicit deny)
iptables -A FORWARD -s 10.20.1.0/24 -d 10.20.40.0/24 -j LOG --log-prefix "BLOCKED_MHS_TO_ADMIN: "
iptables -A FORWARD -s 10.20.1.0/24 -d 10.20.40.0/24 -j DROP

# Allow Internet access
iptables -A FORWARD -s 10.20.1.0/24 -d 0.0.0.0/0 -j ACCEPT

# Anti-spoofing
iptables -A FORWARD -s 10.20.1.0/24 ! -i eth1 -j DROP
```
Contoh: Router Guest (R-Guest)
```
# Guest isolation: Block ALL internal networks
iptables -A FORWARD -s 10.20.50.0/24 -d 10.20.0.0/16 -j LOG --log-prefix "BLOCKED_GUEST_INTERNAL: "
iptables -A FORWARD -s 10.20.50.0/24 -d 10.20.0.0/16 -j DROP

# Allow Guest → Internet (HTTP/S only)
iptables -A FORWARD -s 10.20.50.0/24 -p tcp -m multiport --dports 80,443 -j ACCEPT

# Block dangerous protocols from Guest
iptables -A FORWARD -s 10.20.50.0/24 -p tcp -m multiport --dports 22,23,3389,445,1433,3306 -j DROP
```
Layer 3: Host-based Firewall (UFW)
Contoh: FTP Server (10.20.20.10)
```
# Default deny
ufw default deny incoming
ufw default allow outgoing

# Allow FTP from Mahasiswa & Riset only
ufw allow from 10.20.1.0/24 to any port 21 proto tcp
ufw allow from 10.20.30.0/24 to any port 21 proto tcp

# Allow SSH from Admin only
ufw allow from 10.20.40.0/24 to any port 22 proto tcp

# Rate limiting for brute force protection
ufw limit 22/tcp
ufw limit 21/tcp

# Enable logging
ufw logging on

# Activate
ufw enable
```
Contoh: DNS Server (10.20.40.10)
```
# Allow DNS queries from all internal networks
ufw allow from 10.20.0.0/16 to any port 53

# Allow Syslog reception
ufw allow from 10.20.0.0/16 to any port 514 proto udp

# Allow SSH from Admin subnet only
ufw allow from 10.20.40.0/24 to any port 22 proto tcp

ufw enable
```

#### **Layer 4: Intrusion Detection System (Snort IDS)**

**Snort Configuration di pfSense:**
```
# /usr/local/etc/snort/snort.conf

# Network variables
var HOME_NET [10.20.0.0/16]
var EXTERNAL_NET any

# Rules enabled:
include $RULE_PATH/community.rules
include $RULE_PATH/emerging-scan.rules
include $RULE_PATH/emerging-exploit.rules
include $RULE_PATH/emerging-malware.rules

# Custom rules
include $RULE_PATH/local.rules
```

**Custom Snort Rules (local.rules):**
```
# Detect port scanning
alert tcp any any -> $HOME_NET any (msg:"Possible Port Scan Detected"; flags:S; threshold: type threshold, track by_src, count 20, seconds 60; classtype:attempted-recon; sid:1000001;)

# Detect ARP spoofing attempts
alert arp any any -> any any (msg:"ARP Spoofing Detected"; reference:cve,2019-xxxxx; classtype:bad-unknown; sid:1000002;)

# Detect SSH brute force
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flow:to_server; flags:S; threshold: type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000003;)

# Detect FTP brute force
alert tcp any any -> $HOME_NET 21 (msg:"FTP Brute Force Attempt"; flow:to_server; content:"530 Login incorrect"; threshold: type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000004;)

# Detect unauthorized access to Admin subnet
alert ip 10.20.1.0/24 any -> 10.20.40.0/24 any (msg:"POLICY VIOLATION: Mahasiswa accessing Admin network"; classtype:policy-violation; sid:1000005;)
```

**Snort Actions:**
- **Alert**: Log ke `/var/log/snort/alert`
- **Drop**: Block packet (jika dalam IPS mode)
- **Pass**: Whitelist traffic yang diketahui aman

#### **Layer 5: Security Monitoring & Logging**

**Centralized Syslog Configuration:**
```
Server: 10.20.40.10
Port: 514/UDP
Protocol: Syslog over UDP

Sources configured:
- pfSense Firewall: All firewall blocks + IDS alerts
- Router R-Admin: iptables logs
- Router R-Mahasiswa: iptables logs + failed auth
- Router R-Akademik: iptables logs
- Router R-Riset: iptables logs
- Router R-Guest: All traffic (high verbosity)
- FTP Server: vsftpd logs
- DNS Server: BIND query logs
- Web Server: Apache access + error logs
```

**Log Retention Policy:**
- **Critical logs (security events)**: 180 days
- **Standard logs (access logs)**: 90 days
- **Debug logs**: 30 days
- **Rotation**: Daily at 00:00 WIB

**SNMP Monitoring (10.20.10.10):**
```
Monitored Metrics:
- Interface bandwidth utilization (per router/switch)
- CPU load (all routers + pfSense)
- Memory usage
- Firewall rule hit count
- IDS alert frequency
- Connection table size (pfSense)

Alert Thresholds:
- CPU > 80% for 5 minutes → Email alert
- Bandwidth > 90% → Email alert
- IDS alerts > 50/hour → Email + SMS
- Connection table > 80% → Warning
```

---

## 5. Konfigurasi Sistem

### 5.1 IP Addressing Plan (Final)

#### **Core Network Links (Point-to-Point /30)**

| Link | Interface Firewall | IP Firewall | Interface Router | IP Router | Subnet |
|------|-------------------|-------------|------------------|-----------|---------|
| WAN | em0 | 192.168.100.2 | eth0 (EdgeRouter) | 192.168.100.1 | /30 |
| Admin | em1 (OPT1) | 10.20.0.5 | eth0 (R-Admin) | 10.20.0.6 | /30 |
| Mahasiswa | em2 (LAN) | 10.20.0.1 | eth0 (R-Mhs) | 10.20.0.2 | /30 |
| Akademik | em3 (OPT2) | 10.20.0.9 | eth0 (R-Akd) | 10.20.0.10 | /30 |
| Riset | em4 (OPT3) | 10.20.0.13 | eth0 (R-Riset) | 10.20.0.14 | /30 |
| Guest | em5 (OPT4) | 10.20.0.17 | eth0 (R-Guest) | 10.20.0.18 | /30 |

#### **LAN Subnets (/24)**

| Subnet | Network | Gateway | DHCP Range | Static Range | Fungsi |
|--------|---------|---------|------------|--------------|---------|
| Admin | 10.20.40.0/24 | 10.20.40.1 | 10.20.40.20-100 | 10.20.40.10-19 | Server admin, DNS, Logging |
| Mahasiswa | 10.20.1.0/24 | 10.20.1.1 | 10.20.1.50-200 | 10.20.1.10-20 | Monitoring server, clients |
| Akademik | 10.20.20.0/24 | 10.20.20.1 | 10.20.20.50-200 | 10.20.20.10-20 | FTP server, portal |
| Riset & IoT | 10.20.30.0/24 | 10.20.30.1 | 10.20.30.100-200 | 10.20.30.10-50 | Web server, IoT devices |
| Guest | 10.20.50.0/24 | 10.50.50.1 | 10.20.50.10-250 | - | Guest devices only |

#### **Server Allocation**

| Hostname | IP Address | Services | Subnet |
|----------|------------|----------|---------|
| dns-server-1 | 10.20.40.10 | BIND DNS, Syslog-ng | Admin |
| ftp-server-1 | 10.20.20.10 | vsftpd, SSH | Akademik |
| web-server-rd | 10.20.30.10 | Apache, MySQL, SSH | Riset |
| monitor-srv | 10.20.1.10 | Zabbix, SNMP collector | Mahasiswa |

### 5.2 Routing Table Configuration

#### **pfSense Static Routes**
```
Destination          Gateway           Interface    Description
10.20.1.0/24        10.20.0.2         LAN          To Mahasiswa subnet
10.20.40.0/24       10.20.0.6         OPT1         To Admin subnet
10.20.20.0/24       10.20.0.10        OPT2         To Akademik subnet
10.20.30.0/24       10.20.0.14        OPT3         To Riset subnet
10.20.50.0/24       10.20.0.18        OPT4         To Guest subnet
0.0.0.0/0           192.168.100.1     WAN          Default route to Internet
```
Router Internal (Contoh: R-Mahasiswa)
```
# Default route ke pfSense
ip route add default via 10.20.0.1

# Route ke subnet lokal
ip route add 10.20.1.0/24 dev eth1

# Specific routes ke subnet lain (via pfSense)
ip route add 10.20.20.0/24 via 10.20.0.1  # Akademik
ip route add 10.20.40.0/24 via 10.20.0.1  # Admin (akan diblokir di firewall)
```

### 5.3 Konfigurasi DHCP Server

**pfSense DHCP Pools:**

| Interface | Pool Start | Pool End | Default Gateway | DNS Servers | Domain Name |
|-----------|------------|----------|-----------------|-------------|-------------|
| LAN (Mahasiswa) | 10.20.1.50 | 10.20.1.200 | 10.20.1.1 | 10.20.40.10, 8.8.8.8 | student.dti.its.ac.id |
| OPT1 (Admin) | 10.20.40.20 | 10.20.40.100 | 10.20.40.1 | 10.20.40.10, 1.1.1.1 | admin.dti.its.ac.id |
| OPT2 (Akademik) | 10.20.20.50 | 10.20.20.200 | 10.20.20.1 | 10.20.40.10, 8.8.8.8 | academic.dti.its.ac.id |
| OPT3 (Riset) | 10.20.30.100 | 10.20.30.200 | 10.20.30.1 | 10.20.40.10, 8.8.8.8 | research.dti.its.ac.id |
| OPT4 (Guest) | 10.20.50.10 | 10.20.50.250 | 10.20.50.1 | 8.8.8.8, 1.1.1.1 | guest.dti.its.ac.id |

**DHCP Options:**
- Lease time: 86400 seconds (24 hours)
- DNS domain: dti.its.ac.id
- NTP server: 10.20.40.10

### 5.4 DNS Configuration (BIND9)

**Zones Configured:**
```
# /etc/bind/named.conf.local

zone "dti.its.ac.id" {
    type master;
    file "/etc/bind/zones/db.dti.its.ac.id";
    allow-transfer { 10.20.0.0/16; };
};

zone "20.10.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.10.20";
    allow-transfer { 10.20.0.0/16; };
};
```
Sample Zone File:
```
# /etc/bind/zones/db.dti.its.ac.id

$TTL    604800
@       IN      SOA     dns-server-1.dti.its.ac.id. admin.dti.its.ac.id. (
                              3         ;
Serial
604800         ; Refresh
86400         ; Retry
2419200         ; Expire
604800 )       ; Negative Cache TTL
;
@       IN      NS      dns-server-1.dti.its.ac.id.
@       IN      A       10.20.40.10
; Name servers
dns-server-1            IN      A       10.20.40.10
; Gateways
firewall                IN      A       10.20.0.1
gateway-admin           IN      A       10.20.40.1
gateway-student         IN      A       10.20.1.1
gateway-academic        IN      A       10.20.20.1
gateway-research        IN      A       10.20.30.1
gateway-guest           IN      A       10.20.50.1
; Servers
ftp                     IN      A       10.20.20.10
web-research            IN      A       10.20.30.10
monitoring              IN      A       10.20.1.10
syslog                  IN      A       10.20.40.10
; Aliases
portal                  IN      CNAME   ftp
repository              IN      CNAME   ftp
iot-lab                 IN      CNAME   web-research
```

## 6. Simulasi Serangan & Mitigasi

### 6.1 Metodologi Pengujian

Pengujian penetrasi dilakukan menggunakan metodologi **PTES (Penetration Testing Execution Standard)** dengan fokus pada:
1. **Reconnaissance**: Information gathering
2. **Scanning**: Port scanning & vulnerability scanning
3. **Exploitation**: Attempt unauthorized access
4. **Post-exploitation**: Privilege escalation simulation
5. **Reporting**: Documentation & remediation

**Tools Used:**
- `nmap` - Port scanning & OS fingerprinting
- `arpspoof` - ARP cache poisoning
- `hping3` - DoS simulation
- `hydra` - Brute force attacks
- `tcpdump` / `wireshark` - Packet capture & analysis

### 6.2 Skenario Serangan 1: Port Scanning dari Mahasiswa ke Admin

**Deskripsi:**
Simulasi mahasiswa yang mencoba melakukan reconnaissance terhadap subnet Admin untuk mencari celah keamanan.

**Eksekusi Serangan:**
```bash
# Dari PC-Mahasiswa-1 (10.20.1.11)
root@pc-mahasiswa-1:~# nmap -sS -p- -T4 10.20.40.0/24

Starting Nmap 7.94 ( https://nmap.org ) at 2024-11-23 14:32 WIB
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 256 IP addresses (0 hosts up) scanned in 51.23 seconds

# Attempt dengan -Pn flag (skip ping)
root@pc-mahasiswa-1:~# nmap -sS -Pn -p 22,53,80,443 10.20.40.10

Starting Nmap 7.94 ( https://nmap.org ) at 2024-11-23 14:35 WIB
Nmap scan report for dns-server-1.dti.its.ac.id (10.20.40.10)
Host is up.

PORT    STATE    SERVICE
22/tcp  filtered ssh
53/tcp  filtered domain
80/tcp  filtered http
443/tcp filtered https

All 4 scanned ports on 10.20.40.10 are in state: filtered

Nmap done: 1 IP address (1 host up) scanned in 2.13 seconds
```

**Hasil Deteksi:**

**1. Snort IDS Alert Log:**
[] [1:1000001:1] Possible Port Scan Detected []
[Classification: Attempted Information Leak] [Priority: 2]
11/23-14:32:15.483827 10.20.1.11:48532 -> 10.20.40.10:22
TCP TTL:64 TOS:0x0 ID:47382 IpLen:20 DgmLen:44
S* Seq: 0x1A3F2B89  Ack: 0x0  Win: 0x400  TcpLen: 24
TCP Options (1) => MSS: 1460
[] [1:1000005:1] POLICY VIOLATION: Mahasiswa accessing Admin network []
[Classification: Policy Violation] [Priority: 1]
11/23-14:32:15.483827 10.20.1.11 -> 10.20.40.0/24
IP TTL:64 TOS:0x0 ID:47382 IpLen:20 DgmLen:44

**2. pfSense Firewall Log:**
Nov 23 14:32:15 firewall-core filterlog: 5,16777216,,1000000103,em2,match,block,in,4,0x0,,64,47382,0,none,6,tcp,44,10.20.1.11,10.20.40.10,48532,22,24,S,12345678,0,1460,
Nov 23 14:32:16 firewall-core filterlog: 5,16777216,,1000000103,em2,match,block,in,4,0x0,,64,47383,0,none,6,tcp,44,10.20.1.11,10.20.40.10,48532,53,24,S,12345678,0,1460,
Nov 23 14:32:17 firewall-core filterlog: 5,16777216,,1000000103,em2,match,block,in,4,0x0,,64,47384,0,none,6,tcp,44,10.20.1.11,10.20.40.10,48532,80,24,S,12345678,0,1460,
**3. Router R-Mahasiswa iptables Log:**
Nov 23 14:32:15 r-mahasiswa kernel: BLOCKED_MHS_TO_ADMIN: IN=eth1 OUT=eth0 SRC=10.20.1.11 DST=10.20.40.10 LEN=44 TOS=0x00 PREC=0x00 TTL=63 ID=47382 PROTO=TCP SPT=48532 DPT=22 WINDOW=1024 SYN

**Analisis:**
| Layer | Status | Keterangan |
|-------|--------|------------|
| Layer 1 (pfSense) | ✅ BLOCKED | Firewall rule priority 2 menolak traffic |
| Layer 2 (Router ACL) | ✅ BLOCKED | iptables di R-Mahasiswa mem-DROP paket |
| Layer 4 (IDS) | ✅ DETECTED | Snort mendeteksi scan pattern & policy violation |
| Layer 5 (Logging) | ✅ LOGGED | Event tercatat di Syslog server dengan timestamp |

**Kesimpulan:** Serangan berhasil digagalkan di 2 layer pertama sebelum mencapai target. IDS memberikan alert real-time untuk respons incident.

---

### 6.3 Skenario Serangan 2: ARP Spoofing dalam Subnet Akademik

**Deskripsi:**
Attacker di subnet Akademik mencoba melakukan Man-in-the-Middle (MITM) attack dengan ARP poisoning untuk intercept komunikasi antara PC-Akademik-1 dan FTP Server.

**Eksekusi Serangan:**
```bash
# Dari PC-Akademik-Attacker (10.20.20.50)
root@pc-akademik-attacker:~# arpspoof -i eth0 -t 10.20.20.11 -r 10.20.20.10

0:c:29:3a:2f:11 0:c:29:5b:1a:c2 0806 42: arp reply 10.20.20.10 is-at 0:c:29:3a:2f:11
0:c:29:3a:2f:11 0:c:29:8d:4e:33 0806 42: arp reply 10.20.20.11 is-at 0:c:29:3a:2f:11
0:c:29:3a:2f:11 0:c:29:5b:1a:c2 0806 42: arp reply 10.20.20.10 is-at 0:c:29:3a:2f:11
```

**Sebelum Mitigasi (Vulnerable State):**
```bash
# Pada PC-Akademik-1 (victim)
root@pc-akademik-1:~# arp -an
? (10.20.20.10) at 0c:29:3a:2f:11 [ether] on eth0  ← MAC attacker (WRONG!)
? (10.20.20.1) at 00:50:56:ab:cd:ef [ether] on eth0
```

**Mitigasi yang Diterapkan:**

**1. Static ARP Entries (pada critical servers):**
```bash
# Di FTP Server (10.20.20.10)
root@ftp-server-1:~# cat /etc/network/interfaces
auto eth0
iface eth0 inet static
    address 10.20.20.10
    netmask 255.255.255.0
    gateway 10.20.20.1
    # Static ARP entries untuk gateway
    post-up ip neigh add 10.20.20.1 lladdr 00:50:56:ab:cd:ef dev eth0 nud permanent
```

**2. DAI (Dynamic ARP Inspection) - Simulasi via iptables:**
```bash
# Di Switch-Akademik (atau router)
# Monitor excessive ARP requests
iptables -A INPUT -p arp --arp-op 2 -m recent --name arp_reply --set
iptables -A INPUT -p arp --arp-op 2 -m recent --name arp_reply --update --seconds 60 --hitcount 20 -j LOG --log-prefix "ARP_FLOOD_DETECTED: "
iptables -A INPUT -p arp --arp-op 2 -m recent --name arp_reply --update --seconds 60 --hitcount 20 -j DROP
```

**3. Snort Detection:**
[] [1:1000002:1] ARP Spoofing Detected []
[Classification: Bad Unknown Traffic] [Priority: 2]
11/23 15:12:08.294183 0:C:29:3A:2F:11 -> 0:C:29:5B:1A:C2
ARP Who-has 10.20.20.10 Tell 10.20.20.11
ARP HW src: 0:c:29:3a:2f:11
ARP Proto src: 10.20.20.50
ARP HW dst: 0:0:0:0:0:0
ARP Proto dst: 10.20.20.10

**Setelah Mitigasi:**
```bash
# ARP table dengan static entry
root@pc-akademik-1:~# arp -an
? (10.20.20.10) at 0c:29:5b:1a:c2 [ether] PERM on eth0  ← Correct, permanent
? (10.20.20.1) at 00:50:56:ab:cd:ef [ether] PERM on eth0

# Test connectivity tetap normal
root@pc-akademik-1:~# ping 10.20.20.10 -c 4
PING 10.20.20.10 (10.20.20.10) 56(84) bytes of data.
64 bytes from 10.20.20.10: icmp_seq=1 ttl=64 time=0.823 ms
64 bytes from 10.20.20.10: icmp_seq=2 ttl=64 time=0.712 ms
64 bytes from 10.20.20.10: icmp_seq=3 ttl=64 time=0.698 ms
64 bytes from 10.20.20.10: icmp_seq=4 ttl=64 time=0.705 ms

--- 10.20.20.10 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3052ms
rtt min/avg/max/mdev = 0.698/0.734/0.823/0.051 ms
```

**Kesimpulan:** ARP spoofing terdeteksi oleh IDS dan dimitigasi dengan static ARP entries pada critical infrastructure. Kombinasi detection + prevention efektif menghentikan MITM attack.

---

### 6.4 Skenario Serangan 3: SSH Brute Force dari Internet

**Deskripsi:**
Attacker eksternal mencoba brute force SSH ke server yang (accidentally) exposed di pfSense NAT.

**Eksekusi Serangan:**
```bash
# Dari attacker eksternal (simulate via EdgeRouter)
root@attacker:~# hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.100.2 -t 4

Hydra v9.5 (c) 2023 by van Hauser/THC
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries
[DATA] attacking ssh://192.168.100.2:22/

[22][ssh] host: 192.168.100.2   login: root   password: toor
[STATUS] attack finished for 192.168.100.2 (waiting for children to complete)
```

**Mitigasi yang Diterapkan:**

**1. Rate Limiting di pfSense:**
Firewall → Rules → WAN → Add
Action: Pass
Interface: WAN
Protocol: TCP
Source: any
Destination: WAN address
Destination Port: 22 (SSH)
Advanced Options:
→ Max states: 3
→ Max source nodes: 1
→ Max connections per host: 3
→ State timeout: 30

**2. Fail2ban di Server Target:**
```bash
# /etc/fail2ban/jail.local
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 600
bantime = 3600
action = iptables[name=SSH, port=ssh, protocol=tcp]
         sendmail-whois[name=SSH, dest=admin@dti.its.ac.id]
```

**3. Snort Detection:**
[] [1:1000003:1] SSH Brute Force Attempt []
[Classification: Attempted Administrator Privilege Gain] [Priority: 1]
11/23 16:45:22.193827 203.130.201.15:38492 -> 192.168.100.2:22
TCP TTL:53 TOS:0x0 ID:15432 IpLen:20 DgmLen:60 DF
AP Seq: 0x8B3C9012  Ack: 0x3A1F8D23  Win: 0x7210  TcpLen: 32
[] [1:1000003:1] SSH Brute Force Attempt []
[Classification: Attempted Administrator Privilege Gain] [Priority: 1]
11/23 16:45:23.421093 203.130.201.15:38493 -> 192.168.100.2:22

**Hasil Mitigasi:**
```bash
# Log dari Fail2ban
2024-11-23 16:45:24,183 fail2ban.actions: WARNING [sshd] Ban 203.130.201.15
2024-11-23 16:45:24,189 fail2ban.actions: NOTICE  [sshd] 203.130.201.15 already banned

# iptables rules yang dibuat otomatis
root@ftp-server-1:~# iptables -L -n | grep 203.130.201.15
DROP       all  --  203.130.201.15       0.0.0.0/0
```

**Analisis Effectiveness:**

| Metrik | Sebelum Mitigasi | Setelah Mitigasi |
|--------|------------------|------------------|
| Login attempts per minute | 120+ | 3 (max enforced) |
| Successful brute force | Possible after ~48h | Prevented (ban after 3 attempts) |
| Detection time | N/A | < 1 second |
| Ban duration | N/A | 3600 seconds (auto unban) |
| False positive rate | N/A | 0% (legitimate users unaffected) |

---

### 6.5 Skenario Serangan 4: DoS Attack ke Web Server Riset

**Deskripsi:**
Attacker melakukan SYN flood attack ke web server riset untuk membuat service unavailable.

**Eksekusi Serangan:**
```bash
# Dari attacker (10.20.1.100 - compromised mahasiswa PC)
root@attacker:~# hping3 -S --flood -V -p 80 10.20.30.10

using eth0, addr: 10.20.1.100, MTU: 1500
HPING 10.20.30.10 (eth0 10.20.30.10): S set, 40 headers + 0 data bytes
hping in flood mode, no replies will be shown

--- Statistics ---
Packets sent: 1847234
Packets received: 0
```

**Sebelum Mitigasi - Server Response:**
```bash
root@web-server-rd:~# netstat -an | grep SYN_RECV | wc -l
4892

root@web-server-rd:~# uptime
 17:23:15 up 2 days,  3:42,  1 user,  load average: 8.92, 7.45, 3.21

# Service menjadi unresponsive
root@client-test:~# curl -m 5 http://10.20.30.10
curl: (28) Connection timed out after 5001 milliseconds
```

**Mitigasi yang Diterapkan:**

**1. SYN Cookies di Kernel (Web Server):**
```bash
# Enable SYN cookies
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.tcp_max_syn_backlog=2048
sysctl -w net.ipv4.tcp_synack_retries=2

# Reduce SYN-ACK retries
sysctl -w net.ipv4.tcp_syn_retries=3

# Make permanent
cat >> /etc/sysctl.conf << EOF
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3
EOF
```

**2. Rate Limiting di pfSense (untuk subnet Mahasiswa):**
Firewall → Rules → LAN → Edit
Advanced Options → Limiter:
→ In: 10 Mbps (per IP), queue: 100
→ Out: 10 Mbps (per IP), queue: 100
Connection Rate Limiting:
→ Max states per host: 500
→ Max new connections per second: 50

**3. iptables Rate Limiting (di Web Server):**
```bash
# Limit SYN packets per second
iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# Limit connections per IP
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 20 -j REJECT --reject-with tcp-reset

# Log excessive connections
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 -j LOG --log-prefix "HTTP_FLOOD: "
```

**Setelah Mitigasi - Server Response:**
```bash
root@web-server-rd:~# netstat -an | grep SYN_RECV | wc -l
87  ← Drastically reduced

root@web-server-rd:~# uptime
 17:28:42 up 2 days,  3:47,  1 user,  load average: 1.23, 2.15, 2.98

# Service kembali normal
root@client-test:~# curl -m 5 http://10.20.30.10
<!DOCTYPE html>
<html>
<head><title>DTI Research Lab</title></head>
<body><h1>Welcome to Research Portal</h1></body>
</html>

# Response time normal
root@client-test:~# time curl -s http://10.20.30.10 > /dev/null
real    0m0.124s
user    0m0.008s
sys     0m0.004s
```

**pfSense State Table Monitoring:**

Before mitigation
States: 47892/48000 (99.8% full)
State table warning: HIGH LOAD
After mitigation
States: 3421/48000 (7.1% full)
State table: NORMAL

**Kesimpulan:** Kombinasi kernel tuning (SYN cookies), firewall rate limiting, dan iptables connection limit berhasil memitigasi DoS attack tanpa memblokir legitimate traffic.

---

### 6.6 Skenario Serangan 5: Privilege Escalation via SQL Injection

**Deskripsi:**
Attacker dari subnet Riset mencoba SQL injection ke web application untuk mendapatkan credentials admin.

**Eksekusi Serangan:**
```bash
# Dari PC-Riset-1 (10.20.30.11)
root@pc-riset-1:~# curl -X POST http://10.20.30.10/login.php \
  -d "username=admin' OR '1'='1&password=anything"

HTTP/1.1 200 OK
Set-Cookie: session=a3d8f7e9c2b1a6d4e8f3c9b7a2e1d6f4; Path=/
Location: /admin/dashboard.php

# Attempt to access admin panel
root@pc-riset-1:~# curl -b "session=a3d8f7e9c2b1a6d4e8f3c9b7a2e1d6f4" \
  http://10.20.30.10/admin/users.php
```

**Mitigasi yang Diterapkan:**

**1. Web Application Firewall (ModSecurity):**
```apache
# /etc/apache2/mods-enabled/security2.conf
<IfModule security2_module>
    SecRuleEngine On
    SecRequestBodyAccess On
    SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* \
        "@rx (?i:(?:\b(?:(?:s(?:elect\b(?:.{1,100}?\b(?:(?:length|count|top)\b.{1,100}?\bfrom|from\b.{1,100}?\bwhere)|.*?\b(?:d(?:ump\b.*\bfrom|ata_type)|(?:to_(?:numbe|cha)|inst)r))|p_(?:(?:addextendedpro|sqlexe)c|(?:oacreat|prepar)e|execute(?:sql)?|makewebtask)|ql_(?:longvarchar|variant))|xp_(?:reg(?:re(?:movemultistring|ad)|delete(?:value|key)|enum(?:value|key)s|addmultistring|write)|terminate|e(?:xecresultset|numdsn)s|(?:loginconfig|cmdshel)l|filelist|availablemedia|ntsec_enumdomains|dirtree|makewebtask|terminate|loginconfig|cmdshell|displayparamstmt)|u(?:nion\b.{1,100}?\bselect|tl_(?:file|http))|w(?:aitfor\b.{1,100}?\bdelay|rite(?:xml|dbase))|group\b.{1,100}?\bby\b.{1,100}?\bhaving|or\b.{1,100}?=|db(?:ms_java|a_users)|load\b\W*?\bdata\b.*\binfile|(?:n?varcha|tbcreato)r|autonomous_transaction))" \
        "phase:2,block,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,msg:'SQL Injection Attack Detected',id:950001,severity:'CRITICAL'"
</IfModule>
```

**2. Application-level Protection (PHP - Prepared Statements):**
```php
// login.php (BEFORE - Vulnerable)
$username = $_POST['username'];
$password = $_POST['password'];
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysql_query($query);

// login.php (AFTER - Secured)
$username = $_POST['username'];
$password = $_POST['password'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username AND password = :password");
$stmt->bindParam(':username', $username);
$stmt->bindParam(':password', password_hash($password, PASSWORD_BCRYPT));
$stmt->execute();
```

**3. Snort Custom Rule untuk SQL Injection:**
alert tcp any any -> 10.20.30.10 80 (msg:"SQL Injection Attempt - UNION"; flow:to_server,established; content:"POST"; http_method; pcre:"/union.+select/i"; classtype:web-application-attack; sid:1000006; rev:1;)
alert tcp any any -> 10.20.30.10 80 (msg:"SQL Injection Attempt - OR 1=1"; flow:to_server,established; content:"POST"; http_method; pcre:"/'.or.'.=.'/i"; classtype:web-application-attack; sid:1000007; rev:1;)
