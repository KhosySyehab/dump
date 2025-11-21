auto lo
iface lo inet loopback
# eth0: Ke Core
auto eth0
iface eth0 inet static
    address 10.20.0.10
    netmask 255.255.255.252
    gateway 10.20.0.9
# eth1: LAN
auto eth1
iface eth1 inet static
    address 10.20.30.1
    netmask 255.255.255.0