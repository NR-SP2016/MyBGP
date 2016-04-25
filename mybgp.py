#!/usr/bin/python
import sys
import socket               # Import socket module
import thread
import time

#Global constants

PORT_NUM = 57777                # Reserve a port for your service.
INTERVAL = 60

# argv[0] = this program name
# argv[1] = autonomous system
# argv[2] = network inside(Assuming that you have the network...)
# argv[3-20] = ip addresses to neighbors
# example : mybgp.py 60001 192.168.10.0/24 10.0.0.1 10.0.1.2 ...


#Global variables
routingTable = []		# Routing Table!! You might want to save all ip address and AS number mappings

autoSys = sys.argv[1]
thisNet = sys.argv[2]
neighbors = sys.argv[3:]



# Actual BGP server module. Handles TCP receiving data
def server_bgp(threadName, conn, addr):
    while True:
        data = conn.recv(1024)
        if data[:3] == "REQ":
            print "Received: %s" %(data)
    conn.close()

# TCP Listening module. When connecting, it makes another thread and pass the connection to server_bgp() function
def server_listen(threadName):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = ''
    s.bind((host, PORT_NUM))        # Bind to the port
    s.listen(10)                 # Now wait for client connection.
    while True:
        conn, addr = s.accept()
        print 'Connected from %s' % str(addr)
        # Makes another thread that actually handles the BGP data receiving
        try:
            thread.start_new_thread( server_bgp, ("Thread-SV-BGP", conn, addr) )
        except:
            print "Error: unable to start server thread"


    s.close()                # Close the connection

# BGP client module. It connects to the neighbor's IP.
def client_bgp(threadName, neighbor):
    cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print "Connecting to %s..." % neighbor
    cs.connect((neighbor, PORT_NUM))
    while(True):
        cs.send(makePacketTest())
        time.sleep(INTERVAL)
    cs.close()

# For the testing for now. It sends its AS number and its network(not real IP. for simulation)
def makePacketTest():
    return "REQ|AS%s|%s" % (autoSys, thisNet)

def usage():
    print "%s <ASNumber> <Network> <LinkIP1> <LinkIP2> ..." %(sys.argv[0])
    print "Example: %s 60001 192.168.10.0/24 10.0.0.1 10.0.1.2 ..." %(sys.argv[0])

# Below is the main function!

if(len(sys.argv) <3):
    usage()
    exit(1)

# Starting Server Listening Thread

print "Starting Server Thread..."

try:
    thread.start_new_thread( server_listen, ("Thread-SV-Listening", ) )
except:
    print "Error: unable to start server thread"

print "Waiting 10 sec for starting other nodes..."
time.sleep(10)

# Connecting to all neighbors
for neighbor in neighbors:
    try:
        thread.start_new_thread( client_bgp, ("Thread-CL-BGP", neighbor) )
    except:
        print "Error: unable to start client thread"


while (True):
    #Do Nothing here just waiting because child threads are doing everything...
    time.sleep(1)
# We might handle some command to print routing table or
