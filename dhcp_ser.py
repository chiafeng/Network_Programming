import socket

MAX_BYTES = 65535

#server
SERVERIP = "0.0.0.0"
SERVERPORT = 67

#client
CLIENTIP = "255.255.255.255"
CLIENTPORT = 68

#DHCP fields
OP     = (1).to_bytes(1, 'big')	#1 for request****
HTYPE  = (1).to_bytes(1, 'big')	#10Mb Ethernet
HLEN   = (6).to_bytes(1, 'big')
HOPS   = (0).to_bytes(1, 'big')
XID    = (0).to_bytes(4, 'big')	#transaction ID****
SECS   = (0).to_bytes(2, 'big')	#seconds from request**
FLAGS  = (1 << 15).to_bytes(2, 'big')	#first bit for broadcast****
CIADDR = socket.inet_aton("0.0.0.0")	#valid IP****
YIADDR = socket.inet_aton("0.0.0.0")	#server assigned IP****
SIADDR = socket.inet_aton("0.0.0.0")	#server IP
GIADDR = socket.inet_aton("0.0.0.0")	#gateway IP
CHADDR = (111234).to_bytes(6, 'big')\
			+ (0).to_bytes(10, 'big')	#MAC address
SNAME = (0).to_bytes(64, 'big')
BOOTFILE = (0).to_bytes(128, 'big')
MAGIC_COOKIE = (0x63825363).to_bytes(4, 'big')
DHCP_opt = ""

#IP list
IPList = []
localIP = socket.gethostbyname(socket.gethostname())
state = "LISTENING"
do_DHCP = None	#function pointer

def set_server_sock():
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		sock.bind((SERVERIP, SERVERPORT))
		#sock.connect((CLIENTIP, CLIENTPORT))
		print("socket name: {}".format(sock.getsockname()))

	except:
		raise
	
	return sock

def set_DHCP_opt(phase):
	global DHCP_opt

	if phase == "DISCOVER" :
		DHCP_opt = (53).to_bytes(1, 'big')\
			+ (1).to_bytes(1, 'big')\
			+ (1).to_bytes(1, 'big')
	elif phase == "OFFER" :
		DHCP_opt = (53).to_bytes(1, 'big')\
			+ (1).to_bytes(1, 'big')\
			+ (2).to_bytes(1, 'big')
	elif phase == "REQUEST" :
		DHCP_opt = (53).to_bytes(1, 'big')\
			+ (1).to_bytes(1, 'big')\
			+ (3).to_bytes(1, 'big')
		DHCP_opt += (50).to_bytes(1, 'big')\
			+ (4).to_bytes(1, 'big')\
			+ socket.inet_aton(requestedIP)
	elif phase == "ACK" :
		DHCP_opt = (53).to_bytes(1, 'big')\
			+ (1).to_bytes(1, 'big')\
			+ (5).to_bytes(1, 'big')

	else:
		print("")

	DHCP_opt += (255).to_bytes(1, 'big')	#end option


def send_packet(sock):
	packet = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS\
		+ CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + SNAME + BOOTFILE\
		+ MAGIC_COOKIE + DHCP_opt
	#print(packet)
	
	try:
		sock.sendto(packet, (CLIENTIP, CLIENTPORT))
		print("")
	except:
		raise


def offer(sock):
	global state
	if state != "LISTENING":
		return
	print("DHCP offer....")
	try:
		#assign an IP
		assignedIP = "1.2.3.4"
		while assignedIP in IPList:
			IPNum = socket.inet_aton(assignedIP)
			IPNum = (int.from_bytes(IPNum, 'big') + 1).to_bytes(4, 'big')
			assignedIP = socket.inet_ntoa(IPNum)
		IPList.append(assignedIP)

		print("assignedIP = {}".format(assignedIP))
		print("localIP = {}".format(localIP))

		global OP, YIADDR, SIADDR, GIADDR
		OP     = (2).to_bytes(1, 'big')	#2 for reply
		YIADDR = socket.inet_aton(assignedIP)	#server assigned IP****
		SIADDR = socket.inet_aton(localIP)	#server IP
		GIADDR = socket.inet_aton("0.0.0.0")	#gateway IP
		set_DHCP_opt("OFFER")

		print("")
		send_packet(sock)

	except:
		raise

	state = "OFFER"

def ack(sock):
	global state
	if state != "OFFER":
		return
	print("DHCP ACK....")
	try:

		global OP, CIADDR, YIADDR, SIADDR, GIADDR
		OP     = (2).to_bytes(1, 'big')	#2 for reply
		CIADDR = socket.inet_aton("0.0.0.0")	#valid IP****
		YIADDR = socket.inet_aton("0.0.0.0")	#server assigned IP****
		SIADDR = socket.inet_aton(localIP)	#server IP
		GIADDR = socket.inet_aton("0.0.0.0")	#gateway IP
		set_DHCP_opt("ACK")

		print("")
		send_packet(sock)

	except:
		raise
	print("DHCP finish!!!!")
	state = "LISTENING"


def packetExtract(packet):
	global OP, XID, CIADDR, YIADDR, SIADDR, GIADDR, CHADDR
	try:

		pktPtr = 4
		IN_XID = packet[pktPtr:pktPtr+4]
		#if XID != packet[pktPtr:pktPtr+4]:
		#	raise Exception("XID({}) is not valid".format(int.from_bytes(packet[pktPtr:pktPtr+4], 'big')))
		pktPtr = 12
		IN_CIADDR = packet[pktPtr:pktPtr+4]
		pktPtr = 16
		IN_YIADDR = packet[pktPtr:pktPtr+4]
		pktPtr = 20
		IN_SIADDR = packet[pktPtr:pktPtr+4]
		pktPtr = 24
		IN_GIADDR = packet[pktPtr:pktPtr+4]
		pktPtr = 28
		IN_CHADDR = packet[pktPtr:pktPtr+16]
		print("XID = {}".format(hex(int.from_bytes(IN_XID, 'big'))))
		print("CIADDR = {}".format(socket.inet_ntoa(IN_CIADDR)))
		print("YIADDR = {}".format(socket.inet_ntoa(IN_YIADDR)))
		print("SIADDR = {}".format(socket.inet_ntoa(IN_SIADDR)))
		print("GIADDR = {}".format(socket.inet_ntoa(IN_GIADDR)))
		print("CHADDR = {}".format(int.from_bytes(IN_CHADDR[:6], 'big')))

		pktPtr = 240
		while int.from_bytes(packet[pktPtr:pktPtr+1], 'big') != 53:
			#jump over this option
			pktPtr += int.from_bytes(packet[pktPtr + 1], 'big') + 1
		if int.from_bytes(packet[pktPtr:pktPtr+1], 'big') == 53:
			optLen = int.from_bytes(packet[pktPtr+1:pktPtr+2], 'big')
			pktPtr += 2
			msgType = int.from_bytes(packet[pktPtr:pktPtr+optLen], 'big')
			functionDic = {1:offer, 3:ack}
			if msgType not in functionDic:
				raise Exception("DHCP option extracting fail")
			global do_DHCP
			do_DHCP = functionDic[msgType]
			if msgType == 1:
				print("")
				#do_DHCP = offer
				#offer(sock)
			elif msgType == 2:
					
				if XID != IN_XID:
					raise Exception("XID({}) is not valid".format(int.from_bytes(IN_XID, 'big')))
				#request(sock)
			elif msgType == 3:
				
				if XID != IN_XID:
					raise Exception("XID({}) is not valid".format(int.from_bytes(IN_XID, 'big')))
				#do_DHCP = ack
				#ack(sock)
			elif msgType == 5:
				
				if XID != IN_XID:
					raise Exception("XID({}) is not valid".format(int.from_bytes(IN_XID, 'big')))
				#do nothing
				print("DHCP finish")

		XID = IN_XID
		CIADDR = IN_CIADDR
		YIADDR = IN_YIADDR
		SIADDR = IN_SIADDR
		GIADDR = IN_GIADDR
		CHADDR = IN_CHADDR

	except:
		print("DHCP option extracting fail")
		raise

if __name__ == '__main__':
	print("DHCP server")
	sock = set_server_sock()

	while True:
		try:
			print("------------------------------------------")
			packet = sock.recv(MAX_BYTES)
			#print("received packet: \n{}".format(packet))
			packetExtract(packet)
			#sock.connect((CLIENTIP, CLIENTPORT))
			do_DHCP(sock)
		except:
			continue
	#offer(sock)
	#ack(sock)

	#for i in range(1, 10):
	#	data, address = sock.recvfrom(4)
	#	print(data)