auto lo
iface lo inet loopback

# Ke Edge Router (WAN)
auto eth0
iface eth0 inet static
    address 192.168.100.2
    netmask 255.255.255.252
    gateway 192.168.100.1

# Ke R-Mahasiswa
auto eth1
iface eth1 inet static
    address 10.20.0.1
    netmask 255.255.255.252

# Ke R-Admin
auto eth2
iface eth2 inet static
    address 10.20.0.13
    netmask 255.255.255.252

# Ke R-Guest
auto eth3
iface eth3 inet static
    address 10.20.0.17
    netmask 255.255.255.252

# Ke R-Akademik (Tambahan)
auto eth4
iface eth4 inet static
    address 10.20.0.5
    netmask 255.255.255.252

# Ke R-Riset (Tambahan)
auto eth5
iface eth5 inet static
    address 10.20.0.9
    netmask 255.255.255.252





//
#!/bin/bash
echo "[*] STARTING CORE SETUP..."

# 1. Enable Routing
sysctl -w net.ipv4.ip_forward=1

# 2. Static Routes (Memberitahu Core lokasi User)
# Ingat: IP Gateway di sini adalah IP "Lawan" (Router Cabang)
ip route add 10.20.10.0/24 via 10.20.0.2   # Mhs
ip route add 10.20.40.0/24 via 10.20.0.14  # Admin
ip route add 10.20.50.0/24 via 10.20.0.18  # Guest
ip route add 10.20.20.0/24 via 10.20.0.6   # Akad
ip route add 10.20.30.0/24 via 10.20.0.10  # Riset

# 3. NAT (Agar subnet internal bisa internetan)
iptables -t nat -F
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# 4. FIREWALL RULES (ACL)
iptables -F
iptables -P FORWARD ACCEPT

# [BLOCK] Mahasiswa ke Admin
iptables -A FORWARD -s 10.20.10.0/24 -d 10.20.40.0/24 -j DROP

# [BLOCK] Guest Isolation (Guest gaboleh ke internal manapun)
iptables -A FORWARD -s 10.20.50.0/24 -d 10.20.0.0/16 -j DROP

echo "[*] SETUP DONE!"
//
