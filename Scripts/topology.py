#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController
from functools import partial
from time import sleep
from mininet.cli import CLI
from mininet.link import Link
import os

class SingleSwitchTopo(Topo):
	"Single switch connected to n hosts."
	def build(self, n=2):
		switch_1 = self.addSwitch('switch1');
		switch_2 = self.addSwitch('switch2');
		switch_3 = self.addSwitch('switch3');
		switch_4 = self.addSwitch('switch4');

		sff1 = self.addHost('sff1', ip='10.0.0.100');
		self.addLink(sff1, switch_2);
	  
 
		firewall = self.addHost('firewall', ip='10.0.0.200');
		self.addLink(firewall, switch_1);

		admin = self.addHost('admin', ip='10.0.0.101');
		self.addLink(admin, switch_1);

		dpi = self.addHost('dpi', ip='10.0.0.102');
		self.addLink(dpi, switch_1);

############################## Eployee according to postion ########################
		staff_1 = self.addHost('staff_1', ip='10.0.0.2');
		self.addLink(staff_1, switch_4);

		staff_2 = self.addHost('staff_2', ip='10.0.0.3');
		self.addLink(staff_2, switch_4);

		manager = self.addHost('manager', ip='10.0.0.14');
		self.addLink(manager, switch_4);

		president = self.addHost('president', ip='10.0.0.24');
		self.addLink(president, switch_4);



############################## WebSite #########################
		facebook = self.addHost('facebook', ip='10.0.0.201');
		self.addLink(facebook, switch_3);

		google = self.addHost('google', ip='10.0.0.202');
		self.addLink(google, switch_3);

		naver = self.addHost('naver', ip='10.0.0.203');
		self.addLink(naver, switch_3);

		instagram = self.addHost('instagram', ip='10.0.0.204');
		self.addLink(instagram, switch_3);
################################################################
	# Source Nodes
#	for h in range(n / 2):
 #			 host = self.addHost('h%s' % (h + 1))
  #			 self.addLink(host, switch_3);

	#Destination Nodes
   #	 for h in range(n / 2, n):
	#		 host = self.addHost('h%s' % (h + 1))
	 #		 self.addLink(host, switch_4);

		

		self.addLink(switch_1, switch_2);
		self.addLink(switch_2, switch_3);
		self.addLink(switch_2, switch_4);

def simpleTest():
	os.system("sudo mysql -u root -p mysql < ./schema.sql")
	"Create and test a simple network"

	topo = SingleSwitchTopo(n=4)
	net = Mininet(topo, controller=partial(RemoteController, ip='127.0.0.1', port=6633))
	net.start();
 
	net.pingAll();
	# Inintalize components
	sff = net.get('sff1');
	firewall = net.get('firewall');
	admin = net.get('admin');
	facebook = net.get('facebook');
	google = net.get('google');
	naver = net.get('naver');
	instagram = net.get('instagram');
	dpi = net.get('dpi');


	sff.cmd('../bin/sff sff1-eth0 > /tmp/sff.out &');


	firewall.cmd('cd ../NSF/Firewall; sudo make init');
	firewall.cmd('secu');
	firewall.cmd('sudo ../../bin/firewall firewall-eth0 > /tmp/firewall.out &');

	dpi.cmd('cd ../NSF/DPI; sudo make init');
	dpi.cmd('secu');
	dpi.cmd('sudo ../../bin/dpi dpi-eth0 > /tmp/dpi.out &');

	admin.cmd('cd ../SecurityController');
	admin.cmd('sudo service apache2 stop >> /tmp/webserver.out');
	admin.cmd('sudo service apache2 start >> /tmp/webserver.out');
	admin.cmd('sudo python server.py >> /tmp/webserver.out &');



	# In order to check flow rule
	facebook.cmd('../bin/ipPacketReceiver ', facebook.name, facebook.IP(), ' > /tmp/facebook.out &');
	google.cmd('../bin/ipPacketReceiver ', google.name, google.IP(), ' > /tmp/google.out &');
	naver.cmd('../bin/ipPacketReceiver ', naver.name, naver.IP(), ' > /tmp/naver.out &');
	instagram.cmd('../bin/ipPacketReceiver ', instagram.name, instagram.IP(), ' > /tmp/instagram.out &');



	# Wait server
   # sleep(3);

	# Start Packet Generation
	#packetGenerator.cmd('while true; do ../bin/ipPacketGenerator ', packetGenerator.IP(), destination.IP(), '; sleep 1; done > /tmp/generator.out &');

	# Wait For a While
   # sleep(5);

	# Clear all program
	#packetGenerator.cmd('kill %while');
	#sff.cmd('echo -n end', 'nc -4u -w1', sff.IP(),'8000');
	#sff.cmd('wait', sffProcessID);
	
	CLI(net)
	# Stop Simulation
	net.stop()

if __name__ == '__main__':
	"Tell mininet to print useful information"
	setLogLevel('info')
	simpleTest()
