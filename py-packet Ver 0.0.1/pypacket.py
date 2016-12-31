#!/usr/bin/python
import socket,struct,binascii,os
import pye

print pye.__author__

if os.name == "nt":
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
    s.bind(("YOUR_INTERFACE_IP",0))
    s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
else:
    s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

while True:
    pkt=s.recvfrom(65565)
    unpack=pye.unpack()
    print "\n\n===>> [+] ------------ Ethernet Header----- [+]"
    for i in unpack.eth_header(pkt[0][0:14]).iteritems():
        a,b=i
        print "{} : {} | ".format(a,b),
    print "\n===>> [+] ------------ IP Header ------------[+]"
    for i in unpack.ip_header(pkt[0][14:34]).iteritems():
        a,b=i
        print "{} : {} | ".format(a,b),
    print "\n===>> [+] ------------ Tcp Header ----------- [+]"
    for  i in unpack.tcp_header(pkt[0][34:54]).iteritems():
        a,b=i
        print "{} : {} | ".format(a,b),

    
