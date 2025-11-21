enable
conf t
hostname R-Riset
! Ke Core
interface e0/0
 ip address 172.16.0.18 255.255.255.252
 no shut
! Ke LAN Riset
interface e0/1
 ip address 10.20.30.1 255.255.255.0
 no shut
ip route 0.0.0.0 0.0.0.0 172.16.0.17
end
wr