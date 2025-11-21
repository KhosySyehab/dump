enable
conf t
hostname R-Guest
! Ke Core
interface e0/0
 ip address 172.16.0.14 255.255.255.252
 no shut
! Ke LAN Guest
interface e0/1
 ip address 10.20.50.1 255.255.255.0
 no shut
ip route 0.0.0.0 0.0.0.0 172.16.0.13
end
wr