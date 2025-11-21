auto lo
iface lo inet loopback

# eth0: Ke Core
auto eth0
iface eth0 inet static
    address 10.20.0.14
    netmask 255.255.255.252
    gateway 10.20.0.13

# eth1: Ke LAN Admin
auto eth1
iface eth1 inet static
    address 10.20.40.1
    netmask 255.255.255.0