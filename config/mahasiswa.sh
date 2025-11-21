enable
conf t
hostname R-Mahasiswa
! Ke Core
interface e0/0
 ip address 172.16.0.6 255.255.255.252
 no shut
! Ke LAN Mahasiswa
interface e0/1
 ip address 10.20.10.1 255.255.255.0
 no shut
! Default Route
ip route 0.0.0.0 0.0.0.0 172.16.0.5
! ACL Filter (Tugas Keamanan)
access-list 100 deny ip 10.20.10.0 0.0.0.255 10.20.40.0 0.0.0.255
access-list 100 permit ip any any
interface e0/1
 ip access-group 100 in
end
wr