#!/usr/bin/python

import logging
import subprocess
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import threading

screenlock = threading.Semaphore(value=1)

def scanport(prefix, addr):
	try:
		answer = sr1(ARP(pdst= prefix + str(addr)), timeout=1, verbose=0)
		
		screenlock.acquire()

		if answer == None:
			pass
		else:
			print("[+] Host " + prefix + str(addr) + " is alive")
	except:
		pass
	finally:
		screenlock.release()

print("*************** ARP Scanning script ****************")

if len(sys.argv) != 2:
	print("Usage scapy_script.py [interface]")
	print("Example: scapy_script.py eth0")
	sys.exit()

interface = str(sys.argv[1])

ip = subprocess.check_output("ifconfig " + interface + " | grep 'inet ' | cut -d '	' -f 1 | cut -d 'n' -f 2 | cut -d ' ' -f 2", shell=True).strip()

prefix = ip.split('.')[0] + '.' + ip.split('.')[1] + '.' + ip.split('.')[2] + '.'


reply_ip = list()

for addr in range(0, 254):
	t = threading.Thread(target=scanport, args=(prefix, addr))
	t.start()
