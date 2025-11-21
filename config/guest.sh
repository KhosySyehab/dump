auto lo
iface lo inet loopback

# eth0: Ke Core
auto eth0
iface eth0 inet static
    address 10.20.0.18
    netmask 255.255.255.252
    gateway 10.20.0.17

# eth1: Ke LAN Guest
auto eth1
iface eth1 inet static
    address 10.20.50.1
    netmask 255.255.255.0