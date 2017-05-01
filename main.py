import sys
from Tkinter import *
import ttk
import tkMessageBox
from scapy.all import *
import subprocess
import sched, time
q=Tk()
#monitorconnection
def setup_device():
	try:
		check_kill=subprocess.call(["airmon-ng","check","kill"])
		start_device=subprocess.call(["airmon-ng","start","wlan0"])
		
	except Exception,e:
		print "Error:",e
def putback():
	try:
		stop_kill=subprocess.call(["airmon-ng","stop","wlan0mon"])
		start_net=subprocess.call(["service","network-manager","start"])
		
	except Exception,e:
		print "Error:",e

#kismet
def kisme():
	try:
		kismet=subprocess.call(["kismet"])
		
		
	except Exception,e:
		print "Error:",e
def logkis():
	try:
		kis_log=subprocess.call(["gedit","Kismet.alert"])
		log()
		
	except Exception,e:
		print "Error:",e
def pdfdump():
	try:
		Wifipack=sniff(count=10)
		Wifipack.pdfdump()
		
		
	except Exception,e:
		print "Error:",e

def wifichannel():
    try:
		wifichan=subprocess.call(["python","wifi-channels.py","wlan0"])
		
		
    except Exception,e:
	     print "Error:",e
def pcapdump():
    try:
		pcapdump=subprocess.call(["wireshark","Kismet.pcapdump"])
		
		
    except Exception,e:
	     print "Error:",e
	    
def sqlite():
    try:
		sqlite=subprocess.call(["sqlitebrowser","probes.db"])
		
		
    except Exception,e:
	     print "Error:",e
def gtkwin():
    try:
		gtkwinn=subprocess.call(["python","gtkwindow"])
		
		
    except Exception,e:
	     print "Error:",e


#deauthcode
client = 'FF:FF:FF:FF:FF:FF'



def log():
    ale = open('/root/Desktop/Kismet.alert','r')  
    maac = open('maac','w')
    inval = ['00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF','5C:2E:59:88:C2:D9']
    mac_address_list = []
    p = re.compile('(?:[0-9a-fA-F]:?){12}')
    for line in ale:
        x = re.findall(p, line)
        for mac_address in x:
            if mac_address not in inval and mac_address not in mac_address_list:
                mac_address_list.append(mac_address)
                maac.write(mac_address + "\n")
    maac.close()
    
    b=os.path.getsize("/root//Desktop/Kismet.alert")
    if b>=0:
        tkMessageBox.showinfo("Alert file", "Mac adddress: "+mac_address)
        
    else:
        tkMessageBox.showinfo("No Alert file", "Come again later")
        

def deau():
	ale = open('/root/Desktop/Kismet.alert','r')  
    	inval = ['00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF','5C:2E:59:88:C2:D9']
    	mac_address_list = []
    	p = re.compile('(?:[0-9a-fA-F]:?){12}')
    	for line in ale:
	        x = re.findall(p, line)
        	for mac_address in x:
        	    if mac_address not in inval and mac_address not in mac_address_list:
        	        mac_address_list.append(mac_address)
        	        perform_deauth(mac_address,client,1)
       

def perform_deauth(mac_address, client, count):
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

def probes():
	try:
		proba=subprocess.call(["python","client.db.py","wlan0mon","10","probes.db","office"])
		
		
	except Exception,e:
		print "Error:",e
def qhello():
	qtext=qent.get()	
	qlabel1=Label(q,text=qtext,fg='black').pack()
	return

q.geometry('500x400+200+200')
q.title('WIDS')
#menuconstruction
menubar=Menu(q)
def qopen():
    try:
		nettxtt=subprocess.call(["gedit","Kismet.nettxt"])
		
		
    except Exception,e:
	     print "Error:",e
  
#dialogbox
def qabout():
  qAbout=tkMessageBox.showinfo(title='About',message='this is about box')
  return
def qquit():
  qexit=tkMessageBox.askokcancel(title='Quit',message='Are You Sure')
  if qexit>0:
    q.destroy()
    return
#def qclose():
 # qlabel4=Label(q,text='close application').pack()
  #return
filemenu=Menu(menubar,tearoff=0)
filemenu.add_command(label='Open',command=qopen)
filemenu.add_command(label='Close',command=qquit)
menubar.add_cascade(label='FILE',menu=filemenu)
#def qabout():
#  qlabel5=Label(q,text='info about application').pack()
#  return
helpmenu=Menu(menubar,tearoff=0)
helpmenu.add_command(label='About',command=qabout)
menubar.add_cascade(label='HELP',menu=helpmenu)
q.config(menu=menubar)
#heading
qlabel=Label(text='Wireless Intrusion Prevention System',fg='black')
qlabel.config(font=('Ariel',15,'bold'))#adjust font size
qlabel.config(justify=CENTER)
qlabel.place(x=50,y=10)


#button_monitor_mode
qbutton=Button(text='Monitor mode',command=setup_device,fg='black',bg='grey')
qbutton.place(x=150,y=40)
#button_kismet_terminal
qbutton=Button(text='Kismet terminal',command=kisme,fg='black',bg='grey')
qbutton.place(x=150,y=100)
#prob
qbutton=Button(text='Gather Probereq',command=probes,fg='black',bg='grey')
qbutton.place(x=150,y=160)
#button_threat_neutraliser
qbutton=Button(text='Neutraliser',command=deau,fg='black',bg='grey')
qbutton.place(x=150,y=220)
#button_log_files
qbutton=Button(text='Log files',command=logkis,fg='black',bg='grey')
qbutton.place(x=150,y=280)
qbutton=Button(text='Restore newtork',command=putback,fg='black',bg='grey')
qbutton.place(x=350,y=280)
qbutton=Button(text='visual packets',command=pdfdump,fg='black',bg='grey')
qbutton.place(x=350,y=40)
qbutton=Button(text='get graph',command=wifichannel,fg='black',bg='grey')
qbutton.place(x=350,y=220)
qbutton=Button(text='analize pcap',command=pcapdump,fg='black',bg='grey')
qbutton.place(x=350,y=100)
qbutton=Button(text='database',command=sqlite,fg='black',bg='grey')
qbutton.place(x=350,y=160)
qbutton=Button(text='enter mac manually',command=gtkwin,fg='black',bg='grey')
qbutton.place(x=150,y=340)

#userid_label
q.mainloop()
