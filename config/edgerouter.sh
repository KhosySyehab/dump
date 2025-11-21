enable
conf t
hostname EdgeRouter

! Interface ke Internet (Cloud NAT)
interface e0/0
 ip address dhcp
 no shut

! Interface ke Core (UbuntuDocker-9)
interface e0/1
 ip address 192.168.1.1 255.255.255.0
 no shut

! Routing: Lempar trafik kampus ke Core
ip route 10.20.0.0 255.255.0.0 192.168.1.2
ip route 172.16.0.0 255.240.0.0 192.168.1.2
end
wr