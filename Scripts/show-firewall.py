#	!/usr/bin/env	python

import MySQLdb
import os
import socket
import ipaddress

str_exe_position = "select * from firewall_rule;"
db = MySQLdb.connect(host="localhost", user="root", passwd="secu", db="hackathon")
cur = db.cursor()
cur.execute(str_exe_position)
print ""
print "				Firewall Table"
print ""
print "%10s %10s %10s %10s %10s %10s" % ("Rule ID", "Src IP", "Dest IP", "Start Time", "End Time", "Action")
for row in cur.fetchall():

	str_src_addr_temp = str(ipaddress.IPv4Address(row[1]).reverse_pointer).split('.')
	str_src_addr = str_src_addr_temp[0] + "." + str_src_addr_temp[1] + "." + str_src_addr_temp[2] + "." + str_src_addr_temp[3]

	str_dest_addr_temp = str(ipaddress.IPv4Address(row[2]).reverse_pointer).split('.')
	str_dest_addr = str_dest_addr_temp[0] + "." + str_dest_addr_temp[1] + "." + str_dest_addr_temp[2] + "." + str_dest_addr_temp[3]

	if row[5] == 0:
		print "%10s %10s %10s %10s %10s %10s" % (row[0], str_src_addr, str_dest_addr ,row[3],row[4],"Permit") 

	elif row[5] == 1:
		print "%10s %10s %10s %10s %10s %10s" % (row[0], str_src_addr, str_dest_addr ,row[3],row[4],"Block") 

	elif row[5] == 2:
		print "%10s %10s %10s %10s %10s %10s" % (row[0], str_src_addr, str_dest_addr ,row[3],row[4],"Mirror") 

	else:
		print "%10s %10s %10s %10s %10s %10s" % (row[0], str_src_addr, str_dest_addr ,row[3],row[4],"Advanced") 


db.close()
