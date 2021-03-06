#!/usr/bin/python

import socket
import select
import sys

if len(sys.argv) != 4:
	print("Usage banner_grab.py [IP target] [Start Port] [End Port]")
	print("Example: banner_grab.py 192.168.56.101 15 27")
	sys.exit()

ip = str(sys.argv[1])
start_port = int(sys.argv[2])
end_port = int(sys.argv[3])

for port in range(start_port, end_port):
	try:
		bangrab = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		bangrab.connect((ip, port))
		ready = select.select([bangrab],[],[],1)

		if ready[0]:
			print("TCP Port " + str(port) + " - " + bangrab.recv(4096))
			bangrab.close()
	except:
		pass

