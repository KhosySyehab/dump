enable
conf t
hostname R-Akademik
! Ke Core
interface e0/1
 ip address 172.16.0.10 255.255.255.252
 no shut
! Ke LAN Akademik
interface e0/0
 ip address 10.20.20.1 255.255.255.0
 no shut
ip route 0.0.0.0 0.0.0.0 172.16.0.9
end
wr