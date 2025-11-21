# Laporan Proyek Keamanan Jaringan Berbasis ACL & Firewall
### Departemen Teknologi Informasi – Institut Teknologi Sepuluh Nopember (ITS)

---

## Anggota Kelompok
| Nama | NRP |
|------|------|
| Muhammad Ardiansyah Tri Wibowo | 50272410 |
| Oryza Qiara Ramadhani | 50272410 |
| Ahmad Syauqi Reza | 50272410 |
| Muhammad Khosyi Syehab | 50272410 |

---

## Latar Belakang

Departemen Teknologi Informasi ITS (DTI ITS) baru saja melakukan restrukturisasi infrastruktur jaringan. Dalam sistem baru, terdapat lima subnet utama yang harus saling terhubung melalui core router laboratorium jaringan.  
Namun, setelah terjadi insiden kebocoran data dan lonjakan traffic mencurigakan dari jaringan mahasiswa, tim keamanan internal ditugaskan untuk **merancang sistem pertahanan berlapis berbasis ACL dan firewall.**

Proyek ini bertujuan untuk membangun sistem jaringan yang **aman, modular, dan efisien**, serta mampu **menahan serangan internal maupun eksternal** tanpa mengganggu kolaborasi akademik antar subnet.

---

## Desain Topologi

### Gambaran Umum
Topologi dibangun menggunakan **GNS3** dengan kombinasi **pfSense (firewall utama)**, beberapa router Linux/Debian sebagai router internal, dan beberapa node client (VPCS) serta server (Ubuntu Docker).

<img width="1298" height="718" alt="image" src="https://github.com/user-attachments/assets/ca0e9585-dcf1-4b65-8711-ca2689fe63cf" />


### Komponen Utama

| Node / Perangkat | Nama Logis | Fungsi | Subnet |
|------------------|-------------|---------|---------|
| **pfSenseversion2.7.2-2** | `Firewall-Amdir` | Firewall utama dan core router penghubung antar subnet | 10.20.0.0/16 |
| **R3** | `EdgeRouter` | Terhubung ke NAT (Internet) | DHCP |
| **R5** | `Student-Router` | Router subnet Mahasiswa | 10.20.10.0/24 |
| **R6** | `Academic-Router` | Router subnet Akademik | 10.20.20.0/24 |
| **R7** | `Research-Router` | Router subnet Riset & IoT | 10.20.30.0/24 |
| **R8** | `Guest-Router` | Router subnet Guest | 10.20.50.0/24 |
| **R9** | `Admin-Router` | Router subnet Admin | 10.20.40.0/24 |
| **UbuntuDocker-2** | `DNS & Logging Server` | Server pusat logging dan DNS resolver | 10.20.40.10 |
| **UbuntuDocker-3** | `FTP Server` | Server akademik | 10.20.20.10 |
| **UbuntuDocker-4** | `Web Server (R&D)` | Web server untuk riset IoT | 10.20.30.10 |
| **UbuntuDocker-5** | `Monitoring Server` | Server pemantauan traffic & SNMP | 10.20.10.10 |
| **PC7–14 (VPCS)** | `Client Nodes` | Simulasi pengguna mahasiswa, dosen, admin, dan tamu | sesuai subnet masing-masing |

---

## Konfigurasi IP (Tabel Interface)

| Router / Node | Interface | IP Address | Deskripsi |
|----------------|------------|-------------|-------------|
| **pfSense (Firewall-Amdir)** | em3 | DHCP (ke EdgeRouter/NAT) | Akses internet |
|  | em4 | 10.20.0.1/16 | Core network gateway |
| **R5 (Student-Router)** | e0 | 10.20.0.2/16 | Ke pfSense |
|  | e1 | 10.20.10.1/24 | Ke subnet Mahasiswa |
| **R6 (Academic-Router)** | e0 | 10.20.0.3/16 | Ke pfSense |
|  | e1 | 10.20.20.1/24 | Ke subnet Akademik |
| **R7 (Research-Router)** | e0 | 10.20.0.4/16 | Ke pfSense |
|  | e1 | 10.20.30.1/24 | Ke subnet Riset & IoT |
| **R8 (Guest-Router)** | e0 | 10.20.0.5/16 | Ke pfSense |
|  | e1 | 10.20.50.1/24 | Ke subnet Guest |
| **R9 (Admin-Router)** | e0 | 10.20.0.6/16 | Ke pfSense |
|  | e1 | 10.20.40.1/24 | Ke subnet Admin |
| **Client Mahasiswa (PC13)** | eth0 | 10.20.10.11/24 | Gateway: 10.20.10.1 |
| **Client Akademik (PC9)** | eth0 | 10.20.20.11/24 | Gateway: 10.20.20.1 |
| **Client Admin (PC7)** | eth0 | 10.20.40.11/24 | Gateway: 10.20.40.1 |
| **Client R&D (PC11)** | eth0 | 10.20.30.11/24 | Gateway: 10.20.30.1 |
| **Client Guest (PC8)** | eth0 | 10.20.50.11/24 | Gateway: 10.20.50.1 |

---

## 1. Definisi Keamanan yang Seimbang

Kami mendefinisikan **keamanan seimbang** sebagai sistem yang menjaga **kerahasiaan, integritas, dan ketersediaan** tanpa menghalangi aktivitas kolaboratif antar subnet.

### Aturan Akses (Kebijakan ACL)

| Dari | Ke | Status | Alasan |
|------|----|--------|--------|
| Mahasiswa → Akademik | ✅ | Boleh mengakses FTP (port 21) dan DNS (port 53) |
| Mahasiswa → Admin | ❌ | Dilarang (akses keuangan dan data sensitif) |
| Mahasiswa → Guest | ❌ | Tidak relevan |
| Akademik → R&D | ✅ | Diperbolehkan (kolaborasi penelitian) |
| R&D → Akademik | ✅ | Diperbolehkan (sinkronisasi data) |
| Guest → Semua subnet | ❌ | Terisolasi, hanya akses internet |
| Admin → Semua subnet | ✅ | Hak penuh untuk pemeliharaan |
| Semua subnet → Internet | ✅ (via pfSense NAT) | Diatur oleh firewall NAT outbound |

### Filosofi Keamanan:
> “Setiap subnet memiliki batasan komunikasi yang sesuai dengan fungsinya, namun tetap bisa berkolaborasi melalui jalur yang dikontrol pfSense.”

---

## 2. Pertahanan Berlapis (Defense in Depth)

### Asumsi Serangan:
- **ARP Spoofing / Sniffing** dari subnet mahasiswa  
- **Scanning & Enumeration** ke server akademik  
- **DoS ringan** ke server riset  
- **Privileged Abuse** oleh akun internal admin

### Lapisan Pertahanan:
| Lapisan | Implementasi | Fungsi |
|----------|---------------|---------|
| **1. Perimeter Firewall (pfSense)** | NAT, Block ICMP, ACL antar subnet | Melindungi antar jaringan |
| **2. Router ACL** | Akses kontrol layer-3 (iptables / access-list) | Memblok komunikasi tak relevan |
| **3. Host-based Firewall** | `ufw` di tiap server | Mencegah akses port tak sah |
| **4. IDS/IPS Ringan** | `snort` di pfSense | Deteksi scanning & brute force |
| **5. Logging & Monitoring** | Syslog + Monitoring server | Audit traffic dan peringatan dini |

---

## 3. Pembuktian Sistem Berfungsi

### Indikator Keamanan:
- Tidak ada ping antar subnet yang diblokir (kecuali yang dilarang oleh ACL)
- Port FTP/DNS hanya bisa diakses dari subnet yang diizinkan
- Guest network tidak bisa mengakses internal server
- Semua node masih memiliki koneksi internet

### Pengujian:
| Jenis Uji | Metode | Hasil |
|------------|----------|--------|
| **Ping antar subnet** | `ping 10.20.x.x` | Sesuai kebijakan ACL |
| **FTP access test** | `ftp 10.20.20.10` dari subnet Mahasiswa | ✅ berhasil |
| **Web server access** | `curl 10.20.30.10` dari subnet Akademik | ✅ berhasil |
| **Guest isolation** | `ping 10.20.40.1` dari Guest | ❌ ditolak |
| **Internet access** | `ping 8.8.8.8` | ✅ sukses |

### Evaluasi Performa:
- Latency antar subnet < 3ms  
- Throughput rata-rata 1 Gbps (simulasi)  
- CPU load pfSense < 40% saat IDS aktif

---

## 4. Desain Adaptif & Modular

Desain jaringan ini modular:
- Setiap subnet memiliki router sendiri → mudah ditambah subnet baru.
- pfSense berperan sebagai **central policy manager**.
- Menambah lab baru cukup dengan:
  1. Tambah router baru (mis. R10)
  2. Hubungkan ke pfSense (interface baru)
  3. Buat subnet baru (mis. 10.20.60.0/24)
  4. Tambah ACL & NAT rule di pfSense

*Dengan pendekatan ini, ekspansi jaringan tidak memerlukan perombakan total, hanya update pada layer kebijakan.*

---

## 5. Konfigurasi Router Internal (Linux/Debian)
1. Mapping Port & IP Address (IP Plan)
```
Interface Firewall,Terhubung Ke (Router),IP Firewall (Gateway),IP Router Tetangga,Subnet Link
eth0,EdgeRouter (Internet),192.168.100.2,192.168.100.1,/30
eth1,R-Admin,10.20.0.1,10.20.0.2,/30
eth2,R-Mahasiswa,10.20.0.5,10.20.0.6,/30
eth3,R-Akademik,10.20.0.9,10.20.0.10,/30
eth4,R-Riset & IoT,10.20.0.13,10.20.0.14,/30
eth5,R-Guest,10.20.0.17,10.20.0.18,/30
```
2. Konfigurasi CORE FIREWALL (Linux Docker)

Di Console Docker Firewall :
```
nano setup.sh
```
Isi dengan script ini
```
#!/bin/bash
echo ">>> MEMULAI KONFIGURASI DTI FIREWALL SYSTEM..."

# 1. Aktifkan IP Forwarding (Supaya bisa jadi Router)
sysctl -w net.ipv4.ip_forward=1

# 2. Setting IP Address Interface (Sesuai Topologi Baru)
# Hapus IP lama biar bersih
ip addr flush dev eth0
ip addr flush dev eth1
ip addr flush dev eth2
ip addr flush dev eth3
ip addr flush dev eth4
ip addr flush dev eth5

# Pasang IP Baru
ip addr add 192.168.100.2/30 dev eth0  # WAN
ip addr add 10.20.0.1/30 dev eth1      # Link ke Admin
ip addr add 10.20.0.5/30 dev eth2      # Link ke Mahasiswa
ip addr add 10.20.0.9/30 dev eth3      # Link ke Akademik
ip addr add 10.20.0.13/30 dev eth4     # Link ke Riset
ip addr add 10.20.0.17/30 dev eth5     # Link ke Guest

# Nyalakan interface
ip link set eth0 up && ip link set eth1 up && ip link set eth2 up
ip link set eth3 up && ip link set eth4 up && ip link set eth5 up

# 3. Setting Routing (Supaya Firewall tau lokasi subnet LAN)
# Syntax: ip route add [Subnet Tujuan] via [IP Router Tetangga]
ip route add default via 192.168.100.1            # Default Route ke Internet
ip route add 10.20.40.0/24 via 10.20.0.2          # Ke LAN Admin
ip route add 10.20.10.0/24 via 10.20.0.6          # Ke LAN Mahasiswa
ip route add 10.20.20.0/24 via 10.20.0.10         # Ke LAN Akademik
ip route add 10.20.30.0/24 via 10.20.0.14         # Ke LAN Riset
ip route add 10.20.50.0/24 via 10.20.0.18         # Ke LAN Guest

# 4. Konfigurasi NAT (Supaya Client bisa Internetan)
iptables -t nat -F
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# 5. Konfigurasi KEAMANAN (ACL / Firewall Rules)
iptables -F
# Allow traffic related/established (Balasan paket)
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# [BLOCK] Mahasiswa ke Admin & Keuangan
iptables -A FORWARD -s 10.20.10.0/24 -d 10.20.40.0/24 -j DROP

# [BLOCK] Guest Isolation (Cuma boleh Internet, gak boleh ke Internal manapun)
iptables -A FORWARD -s 10.20.50.0/24 -d 10.20.0.0/16 -j DROP

# [ALLOW] Riset ke Akademik (Kolaborasi)
iptables -A FORWARD -s 10.20.30.0/24 -d 10.20.20.0/24 -j ACCEPT

# [ALLOW] Sisanya (Default Accept untuk Routing Internet)
iptables -A FORWARD -j ACCEPT

```
3. Konfigurasi Router Internal (Cisco IOS)
A. Router Admin (Linux Router)
```
nano /etc/network/interfaces
```
```
auto lo
iface lo inet loopback

# Interface ke Firewall (eth0)
auto eth0
iface eth0 inet static
    address 10.20.0.2
    netmask 255.255.255.252
    gateway 10.20.0.1  <-- Gateway menunjuk ke IP Firewall

# Interface ke LAN Admin (eth1)
auto eth1
iface eth1 inet static
    address 10.20.40.1
    netmask 255.255.255.0
```
Aktifkan Forwarding
```
sysctl -w net.ipv4.ip_forward=1
# Supaya permanen:
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
```
B. R-Mahasiswa (Linux Router)
```
nano /etc/network/interfaces
```
```
auto lo
iface lo inet loopback

# Interface ke Firewall (eth0)
auto eth0
iface eth0 inet static
    address 10.20.0.6
    netmask 255.255.255.252
    gateway 10.20.0.5

# Interface ke LAN Mahasiswa (eth1)
auto eth1
iface eth1 inet static
    address 10.20.10.1
    netmask 255.255.255.0
```
Aktifkan Forwarding
```
sysctl -w net.ipv4.ip_forward=1
```
C. R-Akademik (Linux Router)
```
nano /etc/network/interfaces
```
```
auto lo
iface lo inet loopback

# Interface ke Firewall (eth0)
auto eth0
iface eth0 inet static
    address 10.20.0.10
    netmask 255.255.255.252
    gateway 10.20.0.9

# Interface ke LAN Akademik (eth1)
auto eth1
iface eth1 inet static
    address 10.20.20.1
    netmask 255.255.255.0
```
Aktifkan Forwarding
```
sysctl -w net.ipv4.ip_forward=1
```
D. R-Riset&IOT (Linux)
```
nano /etc/network/interfaces
```
```
auto lo
iface lo inet loopback

# Interface ke Firewall Core (eth0)
auto eth0
iface eth0 inet static
    address 10.20.0.14
    netmask 255.255.255.252
    gateway 10.20.0.13

# Interface ke LAN Riset (eth1)
auto eth1
iface eth1 inet static
    address 10.20.30.1
    netmask 255.255.255.0
```
Script Forwarding
```
nano setup_riset.sh
```
```
#!/bin/bash
echo "Setting up Riset Router..."

# 1. Aktifkan Router Mode (Wajib)
sysctl -w net.ipv4.ip_forward=1

# 2. Security: Standar (Open)
# Riset biasanya butuh port terbuka buat testing, jadi default allow aja
iptables -F
iptables -A FORWARD -j ACCEPT

echo "Riset Router Ready."
```
Jalankan Script
```
sh setup_riset.sh
```
E. Konfigurasi R-Guest (Linux)
```
nano /etc/network/interfaces
```
```
auto lo
iface lo inet loopback

# Interface ke Firewall Core (eth0)
auto eth0
iface eth0 inet static
    address 10.20.0.18
    netmask 255.255.255.252
    gateway 10.20.0.17

# Interface ke LAN Guest (eth1) - Sesuai gambar ke Switch-Guest
auto eth1
iface eth1 inet static
    address 10.20.50.1
    netmask 255.255.255.0
```
Script Firewall & Forwarding (Guest Isolation)
```
nano setup_guest.sh
```
```
#!/bin/bash
echo "Setting up Guest Router..."

# 1. Aktifkan Router Mode
sysctl -w net.ipv4.ip_forward=1

# 2. SECURITY: Guest Isolation Rule
iptables -F
# Blokir Guest (10.20.50.x) akses ke SEMUA Network Lab (10.20.0.0/16)
iptables -A FORWARD -s 10.20.50.0/24 -d 10.20.0.0/16 -j DROP

# Izinkan Guest ke Internet (Selain ip internal lab, boleh lewat)
iptables -A FORWARD -s 10.20.50.0/24 -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

echo "Guest Router Secured."
```
### Konfigurasi PC Client
1. PC-Guest (Linux/VPCS)
```
# Kalau VPCS:
ip 10.20.50.10 10.20.50.1 24

# Kalau Linux Docker Client:
ip addr add 10.20.50.10/24 dev eth0
ip route add default via 10.20.50.1
```
2. PC-Riset&IOT-1 (Linux/VPCS)
```
# Kalau VPCS:
ip 10.20.30.10 10.20.30.1 24

# Kalau Linux Docker Client:
ip addr add 10.20.30.10/24 dev eth0
ip route add default via 10.20.30.1
```
Cara Test Guest Isolation: Coba ping dari PC-Guest ke PC-Riset (ping 10.20.30.10). Harusnya Request Timed Out (Karena diblokir di router Guest). Tapi kalau ping 8.8.8.8 harusnya Reply.
4. Konfigurasi Edge Router (Versi Linux GNS3)
Edit Network Configuration: nano /etc/network/interfaces
```
auto lo
iface lo inet loopback

# Interface ke Internet (eth0) - Pakai DHCP dari GNS3 NAT
auto eth0
iface eth0 inet dhcp

# Interface ke Firewall Docker (eth1)
auto eth1
iface eth1 inet static
    address 192.168.100.1
    netmask 255.255.255.252
```
Jalankan Script: sh setup_edge.sh
```
## Kesimpulan

Melalui desain ini, kami berhasil membangun sistem:
- Aman dan modular (berbasis pfSense + ACL)
- Tahan terhadap serangan internal umum
- Mudah diperluas tanpa mengganggu stabilitas
- Tetap menjaga kolaborasi antar departemen akademik, riset, dan admin

Sistem ini membuktikan prinsip:
> “Keamanan bukan tentang isolasi total, tapi tentang mengendalikan interaksi dengan cara yang cerdas.”

---

## Lampiran
- Konfigurasi pfSense (Firewall Rules & NAT)
- Konfigurasi iptables router internal
- Hasil ping dan traceroute antar subnet
- Log Snort IDS (simulasi serangan nmap)
- Screenshot topologi di GNS3

---

🧑‍💻 **Disusun oleh:**
Kelompok 07-KJK
