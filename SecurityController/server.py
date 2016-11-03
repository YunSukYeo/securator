#	!/usr/bin/env python
import urllib
import urllib2
import requests
import socket
import json
import MySQLdb #DB
import os
import xml.etree.ElementTree as etree
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element,SubElement, dump
from xml.etree import ElementTree
from xml.sax.saxutils import unescape
from xml.etree.ElementTree import ElementTree

 
TCP_IP = '127.0.0.1'
TCP_PORT = 6000
BUFFER_SIZE = 1024  # Normally 1024, but we want fast response
 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
s.listen(1)
#os.system("les >> /tmp/test.txt")


while True:
    print("Now listening...\n")
    conn, addr = s.accept()

    print 'New connection from %s:%d' % (addr[0], addr[1])
    data = conn.recv(BUFFER_SIZE)

    print type(data)
    if not data:
        break
    elif data == 'killsrv':
        conn.close()
        sys.exit()
    else:
        r = requests.get('http://127.0.0.1/qfc.php/api/Policies')
	content = r.content
	root = ET.fromstring(content)

	policy_id = root[0][0].text
	policy_name = root[0][1].text
	policy_position = root[0][2].text
	policy_website = root[0][3].text
	policy_start_time = root[0][4].text
	policy_end_time = root[0][5].text
	policy_action = root[0][6].text	

	employee_ip_list = []	
	web_ip_list = []


#======================DB Part========================
	str_exe_position = "select * from Policies2 where Position like '" + policy_position + "';"
	str_exe_web = "select * from Policies3 where Web_Name like '" + policy_website + "';"

	#print(root[0][0].text)
	#print(root[0][1].text)
	#print(root[0][2].text)
	#print(root[0][3].text)
	#print(root[0][4].text)
	#print(root[0][5].text)
	#print(root[0][6].text)
	#print(Policy)
	#print(content)
	db = MySQLdb.connect(host="localhost", user="root", passwd="secu", db="SC_Position")
	cur = db.cursor()
	#if root[0][2].text == 'staff': 
	cur.execute(str_exe_position)
	for row in cur.fetchall():
		employee_ip_list.append(row[0])
#       		print row[0]
	employee_ip_list_len = len(employee_ip_list)
	db.close()

	#print(employee_ip_list)

	db = MySQLdb.connect(host="localhost", user="root", passwd="secu", db="SC_Web")
	cur = db.cursor()
	cur.execute(str_exe_web)
	for row2 in cur.fetchall():
		web_ip_list.append(row2[0])

	db.close()
	#print(web_ip_list)

#======================Print Part========================
	
	print(policy_id)
	print(policy_name)
	print(employee_ip_list)
	print(employee_ip_list_len)
	print(web_ip_list)
	print(policy_start_time)
	print(policy_end_time)
	print(policy_action)


#======================XML Part_1========================

	hello = Element("hello")
	hello.attrib["xmlns"] = "urn:ietf:params:xml:ns:netconf:base:1.0"
	to = Element("capabilities")
	
	capabilities = Element("capability")
	to.text = " " 
	
	capabilities.text = "urn:ietf:params:netconf:base:1.0"
	hello.append(to)	
	to.append(capabilities)
	
#======================XML Part_2========================

	rpc = Element("rpc")
        rpc.attrib["xmlns"] = "urn:ietf:params:xml:ns:netconf:base:1.0" 
	rpc.attrib["message-id"] = "1"
        elem_edit_config = Element("edit-config")
	elem_target = Element("target")
	elem_config = Element("config")
	elem_policy = Element("policy")
	elem_policy.attrib["xmlns"]="http://skku.com/iot/example/ietf-i2nsf-capability-interface" 
	elem_policy.attrib["xmlns:nc"]="urn:ietf:params:xml:ns:netconf:base:1.0"
	elem_rules = Element("rules")
	elem_rules.attrib["nc:operation"]="create"
	elem_rule_name = Element("rule-name")
	elem_rule_id = Element("rule-id")
	elem_condition = Element("condition")
	elem_packet_sec_condition = Element("packet-sec-condition")
	elem_packet_sec_ipv4 = Element("packet-sec-ipv4")
	elem_pkt_sec_cond_ipv4_src_addr = []

	for i in range(employee_ip_list_len):
		elem_pkt_sec_cond_ipv4_src_addr.append(Element("pkt-sec-cond-ipv4-src-addr"))
	elem_pkt_sec_cond_ipv4_dest_addr = Element("pkt-sec-cond-ipv4-dest-addr")

	elem_generic_context_condition = Element("generic-context-condition")
	elem_schedule = Element("schedule")
	elem_start_time = Element("start-time")
	elem_end_time = Element("end-time")
	elem_action = Element("action")
	elem_action_type = Element("action-type")
	elem_ingress_action = Element("ingress-action")
	elem_permit = Element("permit")
	elem_deny = Element("deny")


	elem_edit_config.text = " "
	temp_elem_target = Element("")
	temp_elem_target.text = "<running/>"
	temp_elem_target = ET.fromstring(temp_elem_target.text)

	elem_config.text = " "
	elem_rule_name.text = '%s' % (policy_name)
	elem_rule_id.text = '%s' % (policy_id) 
	elem_condition.text = " "
	elem_packet_sec_condition.text = " "
	elem_packet_sec_ipv4.text = " "
	elem_pkt_sec_cond_ipv4_dest_addr.text = '%s' % (web_ip_list[0])
	elem_generic_context_condition.text = " "
	elem_schedule.text = " "
	elem_start_time.text = '%s' % (policy_start_time)
	elem_end_time.text = '%s' % (policy_end_time)
	elem_action.text = " "
	elem_action_type.text = " "
	elem_ingress_action.text = " "

	if 'Block' in policy_action :
		elem_deny.text = "true"
	else :
		elem_permit.text = "true"


	rpc.append(elem_edit_config)
	elem_edit_config.append(elem_target)
	elem_target.append(temp_elem_target)
	elem_edit_config.append(elem_config)
	elem_config.append(elem_policy)
	elem_policy.append(elem_rules)
	elem_rules.append(elem_rule_name)
	elem_rules.append(elem_rule_id)
	elem_rules.append(elem_condition)
	elem_condition.append(elem_packet_sec_condition)
	elem_packet_sec_condition.append(elem_packet_sec_ipv4)

	
	for i in range(employee_ip_list_len):
		elem_pkt_sec_cond_ipv4_src_addr[i].text = '%s' % (employee_ip_list[i])
		elem_packet_sec_ipv4.append(elem_pkt_sec_cond_ipv4_src_addr[i])

	elem_packet_sec_ipv4.append(elem_pkt_sec_cond_ipv4_dest_addr)
	elem_condition.append(elem_generic_context_condition)
	elem_generic_context_condition.append(elem_schedule)
	elem_schedule.append(elem_start_time)
	elem_schedule.append(elem_end_time)
	elem_rules.append(elem_action)
	elem_action.append(elem_action_type)
	elem_action_type.append(elem_ingress_action)

	if 'Block' in policy_action :
		elem_ingress_action.append(elem_deny)
	else :
		elem_ingress_action.append(elem_permit)




#======================XML part_3========================


	elem_under_rpc = Element("rpc")
	elem_under_rpc.attrib["xmlns"]="urn:ietf:params:xml:ns:netconf:base:1.0" 
	elem_under_rpc.attrib["message-id"]="2"
	temp_elem_under_rpc = Element("")
	temp_elem_under_rpc.text = "<close-session/>"
	temp_elem_under_rpc = ET.fromstring(temp_elem_under_rpc.text)
#	elem_under_rpc = ET.fromstring(elem_under_rpc.text)
	elem_under_rpc.append(temp_elem_under_rpc)
#======================XML def========================
	def indent(elem, level=0):
		i = "\n" + level*" "
		if len(elem):
			if not elem.text or not elem.text.strip():
				elem.text = i + ""
			if not elem.tail or not elem.text.strip():
				elem.tail = i
			for elem in elem:
				indent(elem, level+1)
			if not elem.tail or not elem.tail.strip():
				elem.tail = i
			for elem in elem:
				indent(elem, level+2)
			if not elem.tail or not elem.tail.strip():
				elem.tail = i
		else:
			if level and (not elem.tail or not elem.tail.strip()):
				elem.tail = i

	f_write = open("./policy/firewall.xml", 'w')	
	print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
	data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	f_write.write(data)
	indent(hello)
	dump(hello)
	ElementTree(hello).write("test.xml")

	f_read = open("test.xml", 'r')
	while True:
		line = f_read.readline()
		if not line: break
		f_write.write(line)
	f_read.close()

	print("]]>]]>")
	print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")	
	data = "]]>]]>\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	f_write.write(data)
	indent(rpc)
	dump(rpc)
	ElementTree(rpc).write("test.xml")

	f_read = open("test.xml", 'r')
	while True:
		line = f_read.readline()
		if not line: break
		f_write.write(line)
	f_read.close()

	print("]]>]]>")
	print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
	data = "]]>]]>\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	indent(elem_under_rpc)
	dump(elem_under_rpc)
	f_write.write(data)
	ElementTree(elem_under_rpc).write("test.xml")

	f_read = open("test.xml", 'r')
	while True:
		line = f_read.readline()
		if not line: break
		f_write.write(line)
	f_read.close()

	print("]]>]]>")
	data = "]]>]]>"
	f_write.write(data)


	f_write.close()

	os.system("rm test.xml")
	os.system("sudo ../../confd-6.2/bin/netconf-console --host 10.0.0.200 policy/firewall.xml >> /tmp/webserver.out" )

print 'Connection address:', addr



# r = requests.get('http://127.0.0.1/qfc.php/api/Policies')






conn.close()
