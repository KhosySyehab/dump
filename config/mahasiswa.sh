auto lo
iface lo inet loopback

# eth0: Ke Core (Uplink)
auto eth0
iface eth0 inet static
    address 10.20.0.2
    netmask 255.255.255.252
    gateway 10.20.0.1

# eth1: Ke LAN (Switch Mahasiswa)
auto eth1
iface eth1 inet static
    address 10.20.10.1
    netmask 255.255.255.0