auto lo
iface lo inet loopback

# Ke Internet (Awan)
auto eth0
iface eth0 inet dhcp

# Ke Core Router
auto eth1
iface eth1 inet static
    address 192.168.100.1
    netmask 255.255.255.252