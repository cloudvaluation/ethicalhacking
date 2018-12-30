#!/usr/bin/python
import optparse
from scapy.all import *
#import logging
#import subprocess
#logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import threading

screenlock = threading.Semaphore(value=1)

def tcpxmasscan(tgtHost, tgtPort):
	try:
		#Change the flags to FPU: FIN, PUSH, URG
		answer = sr1(IP(dst=tgtHost)/TCP(dport=tgtPort, flags = 'FPU'), timeout=1, verbose=0)
		screenlock.acquire()

		if answer[TCP].flags == 'RA':
			print("[+] Host " + str(tgtHost) + " is alive and listenning on port " + str(tgtPort))
		else:
			pass
	except:
		pass
	finally:
		screenlock.release()

#Create parser to parse arguments of the scanning tool
parser = optparse.OptionParser("Usage: -H <Target Hosts> -p <Target Ports)")
parser.add_option('-H', dest='tgtHost', type='string', help='Hosts separated by /')
parser.add_option('-p', dest='tgtPort', type='string', help='Ports serparated by /')

(options,args) = parser.parse_args()

tgtHost = str(options.tgtHost).split('/')
tgtPort = str(options.tgtPort).split('/')

mask = str(tgtHost[0]).split('.')
prefix = mask[0] + '.' + mask[1] + '.' + mask[2] + '.'

startHost = int(mask[3])
 
if len(tgtHost) == 1:
	endHost = startHost
else:
	endHost = int(tgtHost[1])

startPort = int(tgtPort[0])

if len(tgtPort)==1:
	endPort = startPort
else:
	endPort = int(tgtPort[1])

#Loop on hosts and ports (including the upper end)
for host in range(startHost, endHost+1):
	for port in range(startPort, endPort+1):
		t = threading.Thread(target= tcpxmasscan, args=(prefix + str(host), port))
		t.start()
