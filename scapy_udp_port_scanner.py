#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
import sys

if len(sys.argv) != 4:
	print("Usage scapy_udp_port_scanner.py [target IP] [1] [100]")
	print("Example: scapy_udp_port_scanner.py 192.168.56.101 1 100")
	sys.exit()

ip = str(sys.argv[1])
start_port = int(sys.argv[2])
end_port = int(sys.argv[3])

port_list = list()

for port in range(start_port, end_port):
	answer = sr1(IP(dst=ip)/UDP(dport = port), timeout=5,verbose=0)
	time.sleep(1)
	if answer == None:
		port_list.append(port)
	else:
		pass

for elt in port_list:
	print(elt)

