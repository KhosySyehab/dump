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

![Topologi GNS3](topologi.png)

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
Di GNS3, pastikan kabel dicolokkan sesuai urutan interface eth di Docker container:
```
Interface Docker,Terhubung Ke,IP Address (CIDR),Keterangan
eth0,Edge Router (Internet),192.168.100.2/30,Uplink WAN
eth1,R-Mahasiswa,10.20.0.1/30,Gateway untuk Mahasiswa
eth2,R-Admin,10.20.0.13/30,Gateway untuk Admin
eth3,R-Guest,10.20.0.17/30,Gateway untuk Guest
```
### Konfigurasi IP Address (Persisten)
- Klik kanan Node Docker > Edit config > Edit /etc/network/interfaces. Atau edit manual dari terminal: nano /etc/network/interfaces.

```
# /etc/network/interfaces

auto lo
iface lo inet loopback

# 1. WAN (Ke Edge Router/Internet)
auto eth0
iface eth0 inet static
    address 192.168.100.2
    netmask 255.255.255.252
    gateway 192.168.100.1

# 2. Link ke Mahasiswa
auto eth1
iface eth1 inet static
    address 10.20.0.1
    netmask 255.255.255.252

# 3. Link ke Admin
auto eth2
iface eth2 inet static
    address 10.20.0.13
    netmask 255.255.255.252

# 4. Link ke Guest
auto eth3
iface eth3 inet static
    address 10.20.0.17
    netmask 255.255.255.252
```
### Script Setup (Routing & Firewall)

file: setup_firewall.sh

```
#!/bin/bash

echo "[*] Memulai Konfigurasi Core Firewall..."

# --- A. SYSTEM TUNING ---
# Mengaktifkan IP Forwarding (Wajib agar bisa merouting paket)
sysctl -w net.ipv4.ip_forward=1

# --- B. STATIC ROUTING ---
# Menambahkan rute ke subnet di belakang Router Internal
# Syntax: ip route add [SUBNET_TUJUAN] via [IP_ROUTER_NEXT_HOP]

echo "[+] Menambahkan Static Routes..."
# Ke Network Mahasiswa (Lewat R-Mhs: 10.20.0.2)
ip route add 10.20.10.0/24 via 10.20.0.2

# Ke Network Admin (Lewat R-Admin: 10.20.0.14)
ip route add 10.20.40.0/24 via 10.20.0.14

# Ke Network Guest (Lewat R-Guest: 10.20.0.18)
ip route add 10.20.50.0/24 via 10.20.0.18

# (Tambahkan untuk Akademik/Riset jika ada, sesuaikan IP Next Hop-nya)


# --- C. FIREWALL & NAT (IPTABLES) ---
echo "[+] Mengonfigurasi IPTables..."

# 1. Flush (Bersihkan) rule lama
iptables -F
iptables -t nat -F

# 2. NAT Masquerade (Agar semua subnet bisa Internetan)
# Traffic yang keluar lewat eth0 (WAN) akan di-NAT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# 3. SECURITY POLICIES (ACL)

# Policy: Izinkan paket yang sudah establish (Reply packet)
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# [BLOCK] Mahasiswa ke Admin (Cegah akses data sensitif)
iptables -A FORWARD -s 10.20.10.0/24 -d 10.20.40.0/24 -j DROP

# [BLOCK] Guest Isolation (Guest tidak boleh ke Network Internal manapun 10.20.x.x)
iptables -A FORWARD -s 10.20.50.0/24 -d 10.20.0.0/16 -j DROP

# [ALLOW] Sisanya diizinkan (Default Allow untuk Internet & routing wajar)
iptables -A FORWARD -j ACCEPT

echo "[*] Konfigurasi Selesai! Sistem Siap."
```

### Verifikasi Keberhasilan

Di PC Client.

1. Cek Internet:
   - Dari PC Mahasiswa: ping 8.8.8.8
   - Harus Reply (Tanda Routing Default & NAT jalan).
2. Cek Routing Internal:
   - Dari PC Admin: ping 10.20.10.10 (IP PC Mahasiswa)
   - Harus Reply (Tanda Static Route jalan).
3. Cek Keamanan (Firewall):
   - Dari PC Mahasiswa: ping 10.20.40.10 (IP PC Admin)
   - Harus RTO / Destination Net Unreachable (Tanda IPTables rule DROP jalan).

*Pastikan Edge Router (Cisco/Linux di atasnya Docker ini) memiliki rute balik agar paket internet bisa kembali ke lab.

Di Edge Router:
```
ip route 10.20.0.0 255.255.0.0 192.168.100.2
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
