#!/usr/bin/python

import sys
from scapy.all import *
import sqlite3

clientprobes = set()

def InsertInDB(mac,ssid):
	
	connection.execute("insert into clients (location,macaddr,probedssid) values (?,?,?);",(sys.argv[4],mac,ssid))
	connection.commit()

def PacketHandler(pkt) :

	if pkt.haslayer(Dot11ProbeReq) :
	
		if len(pkt.info) > 0 :
			testcase = pkt.addr2 + '...' + pkt.info
			if testcase not in clientprobes :
				clientprobes.add(testcase)
				print "New probe found: " + pkt.addr2 + pkt.info

				InsertInDB(pkt.addr2,pkt.info)

				print "\n........Client probe table .........\n"
				counter = 1
				for probe in clientprobes :
					[client,ssid]=probe.split('...')
					print counter, client , ssid
					counter = counter + 1

					
				print "\n.......Client probe table.........\n"

connection = sqlite3.connect(sys.argv[3])
sniff(iface = sys.argv[1], count = int ( sys.argv[2] ) , prn = PacketHandler)
connection.close()
