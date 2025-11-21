enable
conf t
hostname R-Admin
! Ke Core
interface e0/1
 ip address 172.16.0.2 255.255.255.252
 no shut
! Ke LAN Admin
interface e0/0
 ip address 10.20.40.1 255.255.255.0
 no shut
! Default Route ke Core
ip route 0.0.0.0 0.0.0.0 172.16.0.1
end
wr