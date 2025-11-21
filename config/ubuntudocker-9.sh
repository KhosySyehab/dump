# 1. Hapus IP lama (opsional, biar bersih)
ip addr flush dev eth0
ip addr flush dev eth1
ip addr flush dev eth2
ip addr flush dev eth3
ip addr flush dev eth4
ip addr flush dev eth5

# 2. Pasang IP Address (Sesuai Peta di atas)
# Arah ke Admin
ip addr add 172.16.0.1/30 dev eth0
# Arah ke Edge/Internet
ip addr add 192.168.1.2/24 dev eth1
# Arah ke Mahasiswa (UbuntuDocker-7)
ip addr add 172.16.0.5/30 dev eth2
# Arah ke Akademik (UbuntuDocker-5)
ip addr add 172.16.0.9/30 dev eth3
# Arah ke Guest (UbuntuDocker-8)
ip addr add 172.16.0.13/30 dev eth4
# Arah ke Riset (UbuntuDocker-6)
ip addr add 172.16.0.17/30 dev eth5

# 3. Aktifkan Mode Router (Forwarding)
sysctl -w net.ipv4.ip_forward=1

# 4. Routing Default ke Internet (Lewat EdgeRouter)
ip route add default via 192.168.1.1

# 5. Routing Balik ke Subnet Kampus (Agar Core tau user ada dimana)
ip route add 10.20.40.0/24 via 172.16.0.2
ip route add 10.20.10.0/24 via 172.16.0.6
ip route add 10.20.20.0/24 via 172.16.0.10
ip route add 10.20.50.0/24 via 172.16.0.14
ip route add 10.20.30.0/24 via 172.16.0.18

# 6. NAT (Agar semua bisa internetan)
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE