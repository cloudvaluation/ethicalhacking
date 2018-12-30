#!/usr/bin/python

from scapy.all import *
import logging
import subprocess
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import threading

screenlock = threading.Semaphore(value=1)

def tcpackscan(prefix, addr):
	try:
		answer = sr1(IP(dst=prefix+str(addr))/TCP(dport=80, flags = 'A'), timeout=1, verbose=0)
		screenlock.acquire()

		if int(answer[TCP].flags) == 4:
			print("[+] Host " + prefix + str(addr) + " is alive")
		else:
			pass
	except:
		pass
	finally:
		screenlock.release()

if len(sys.argv) != 2:
	print("Usage scapy_tcp_ACK_discovery.py [interface]")
	print("Example: scapy_tcp_ACK_discovery.py eth0")
	sys.exit()

interface = str(sys.argv[1])

ip = subprocess.check_output("ifconfig " + interface + " | grep 'inet' | cut -d '	' -f 1 | cut -d 'n' -f 2 | cut -d ' ' -f 2", shell=True).strip()

prefix = ip.split('.')[0] + '.' + ip.split('.')[1] + '.' + ip.split('.')[2] + '.'

reply_ip = list()

for addr in range(100,254):
	t = threading.Thread(target=tcpackscan, args=(prefix, addr))
	t.start()

#for addr in range(100,110):
#	answer = sr1(IP(dst=prefix + str(addr)) / TCP(dport=80, flags = 'A'), timeout=1, verbose=0)
#	try:
#		if int(answer[TCP].flags) == 4:
#			reply_ip.append(prefix + str(addr))
#	except:
#		pass

#for elt in reply_ip:
#	print(elt)

