#!/usr/bin/python
import sys
import socket               # Import socket module
import thread
import time
import MyPacket
import random

#Global constants

PORT_NUM = 57777                # Reserve a port for your service.
INTERVAL = 30

# argv[0] = this program name
# argv[1] = autonomous system
# argv[2] = network inside(Assuming that you have the network...)
# argv[3-20] = ip addresses to neighbors
# example : mybgp.py 60001 192.168.10.0/24 10.0.0.1 10.0.1.2 ...


#Global variables
routingTable = []		# Routing Table!! You might want to save all ip address and AS number mappings here
neighbors = []


KEY_TYPE_REQUEST = 1
AGE_LIFE = 10
BUFFER_SIZE = 1024
DEBUG = True

def d(msg):
    if(DEBUG):
        print(msg)

"""
HexByteConversion

Convert a byte string to it's hex representation for output or visa versa.

ByteToHex converts byte string "\xFF\xFE\x00\x01" to the string "FF FE 00 01"
HexToByte converts string "FF FE 00 01" to the byte string "\xFF\xFE\x00\x01"
"""

#-------------------------------------------------------------------------------

def ByteToHex( byteStr ):
    """
    Convert a byte string to it's hex string representation e.g. for output.
    """

    # Uses list comprehension which is a fractionally faster implementation than
    # the alternative, more readable, implementation below
    #
    #    hex = []
    #    for aChar in byteStr:
    #        hex.append( "%02X " % ord( aChar ) )
    #
    #    return ''.join( hex ).strip()

    return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()

#-------------------------------------------------------------------------------

def HexToByte( hexStr ):
    """
    Convert a string hex byte values into a byte string. The Hex Byte values may
    or may not be space separated.
    """
    # The list comprehension implementation is fractionally slower in this case
    #
    #    hexStr = ''.join( hexStr.split(" ") )
    #    return ''.join( ["%c" % chr( int ( hexStr[i:i+2],16 ) ) \
    #                                   for i in range(0, len( hexStr ), 2) ] )

    bytes = []

    hexStr = ''.join( hexStr.split(" ") )

    for i in range(0, len(hexStr), 2):
        bytes.append( chr( int (hexStr[i:i+2], 16 ) ) )

    return ''.join( bytes )

# Actual BGP server module. Handles TCP receiving data
def server_bgp(threadName, conn, addr):
    while True:
        #buf = bytearray(BUFFER_SIZE)
        #recved = conn.recv_into(buf, BUFFER_SIZE)
        buf = None
        try:
            buf = conn.recv(BUFFER_SIZE)
        except socket.error, e:
            print "Socket Error: %s" % str(e)
        #d("Received: %s" % ByteToHex(buf))
        recved = 0
        if(buf is not None):
            recved = len(buf)
        if(recved > 19):
            (dataType, network, subnet, linkCost, pathVector) = MyPacket.decode(buf)
            if dataType == KEY_TYPE_REQUEST:
                neighbor = findNeighborByIp(addr[0])
                if neighbor is None:
                    neighbors.append({"ip" : addr[0], "age": AGE_LIFE, "socket": conn})
                else:
                    neighbor.update({"age" : AGE_LIFE})
                if determineLoop(pathVector):
                    d("Loop detected. Ignoring...")
                    continue
                print "Received: net:%s sub:%s path:%s" %(network, subnet, pathVector)

                # Update Routing Table!
                forward = ""
                if(pathVector[0] == pathVector[-1]):
                    forward = "Direct"
                else:
                    forward = "Routed"
                routingRow = {"network":network, "subnet":subnet, "AS":pathVector[-1], "neighbor": pathVector[0], "linkCost": linkCost, "forward": forward}
                if(len(routingTable) == 0):
                    routingTable.append(routingRow)
                else:
                    newcomer = True
                    for route in routingTable:
                        if(route["network"] == network):
                            newcomer = False
                            #Updates the route only if the cost is smaller to make Shortest path!
                            if(route["linkCost"] > linkCost):
                                route["linkCost"] = linkCost
                                route.update(routingRow)
                                d("Link cost is updated with smaller one")
                    if(newcomer):
                        routingTable.append(routingRow)

                # Finished! Displaying Routing Table
                displayRoutingTable()

                #Now we need to add this AS first line and send it to other neighbors
                #Only floods to the other neighbors if it is set flooding or
                #the network is not in excluding list!!
                if(flooding or network not in excluding):
                    pathVector.insert(0, autoSys)
                    for neighbor in neighbors:
                        if(neighbor["ip"] == addr[0]):
                            continue
                        elif "socket" in neighbor:
                            s = neighbor["socket"]
                            pkt = MyPacket.encode(KEY_TYPE_REQUEST, network, subnet, pathVector)
                            s.send(pkt)
        if(recved == 0):
            break
    conn.close()

# TCP Listening module. When connecting, it makes another thread and pass the connection to server_bgp() function
def server_listen(threadName):
    ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = ''
    ss.bind((host, PORT_NUM))        # Bind to the port
    ss.listen(10)                 # Now wait for client connection.
    while True:
        conn, addr = ss.accept()
        print 'Connected from %s' % str(addr)
        # Makes another thread that actually handles the BGP data receiving
        try:
            thread.start_new_thread( server_bgp, ("Thread-SV-BGP", conn, addr) )
        except:
            print "Error: unable to start server thread"
    ss.close()                # Close the connection

# BGP client module. It connects to the neighbor's IP.
def client_bgp(threadName, neighbor):
    while True:
        cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        d("Connecting to %s..." % neighbor["ip"])
        try:
            cs.connect((neighbor["ip"], PORT_NUM))
            d("Connected to : %s" % neighbor["ip"])
            neighbor.update({"socket": cs})
            while(True):
                pkt = MyPacket.encode(KEY_TYPE_REQUEST, thisNet, thisSub, [autoSys])
                #d("sending:" + ByteToHex(pkt))
                cs.send(pkt)
                time.sleep(INTERVAL)
        except socket.error, e:
            print "Socket Error: %s" % str(e)
        cs.close()

def determineLoop(pathVector):
    return autoSys in pathVector

def findNeighborByIp(ipAddress):
    for neighbor in neighbors:
        if neighbor["ip"] == ipAddress:
            return neighbor
    return None

def displayRoutingTable():
    print "network\t\tsubnet\t\tAS\tneighbor\tforwardTo"
    for route in routingTable:
        print "%s\t%s\t%s\t%s\t\t%s" % (route["network"], route["subnet"], route["AS"], route["neighbor"], route["forward"])

def aging_thread(threadName):
    while True:
        time.sleep(INTERVAL)
        aging()
def aging():
    tobeDeleted = []
    for neighbor in neighbors:
        neighbor["age"] -= 1
        if(neighbor["age"] <= 0):
            tobeDeleted.append(neighbor)
            neighbor["socket"].close()
    for neighbor in tobeDeleted:
        neighbors.remove(neighbor)

# For the testing for now. It sends its AS number and its network(not real IP. for simulation)
def makePacketTest():
    return "REQ|%s|%s|%s" % (thisNet, thisSub, autoSys)

def parsePolicy(options):
    policy = []
    parsing = False
    for i in range(0, len(options)):
        if(options(i) == "-p"):
            parsing = True
        else if(options(i)[0] == "-"):
            parsing = False
        else:
            policy.append(options[i])
    return policy

def parseLinks(options):
    links = []
    parsing = False
    for i in range(0, len(options)):
        if(options(i) == "-p"):
            parsing = True
        elif(options(i)[0] == "-"):
            parsing = False
        else:
            links.append(options[i])
    return links

def usage():
    print "%s <ASNumber> <Network> <Subnet> -p <NoFlooding/Exclude> <Network to be excluded> -l <LinkIP1> <LinkIP2> ..." %(sys.argv[0])
    print "Example1: %s 60001 192.168.10.0 255.255.255.0 -l 10.0.0.1 10.0.1.2 ..." %(sys.argv[0])
    print "Example2: %s 60001 192.168.10.0 255.255.255.0 -p Exclude 192.168.40.0 -l 10.0.0.1 10.0.1.2 ..." %(sys.argv[0])

# Below is the main function!
if(len(sys.argv) <5):
    usage()
    exit(1)

autoSys = int(sys.argv[1])
thisNet = sys.argv[2]
thisSub = sys.argv[3]

policy = parsePolicy(sys.argv[4:])
links = parseLinks(sys.argv[4:])
flooding = True
excluding = []

if policy[0] == "NoFlooding":
    flooding = False
else if policy[0] == "Exclude":
    for exclude in policy[1:]:
        excluding.append(exclude)

# Registering neighbor links with random costs
for neighbor in links:
    neighbors.append({"ip": neighbor, "age": AGE_LIFE, "cost": int(random.random()*100%10)})

# Append routing table for myself
routingRow = {"network":thisNet, "subnet":thisSub, "AS":autoSys, "neighbor": autoSys, "linkCost":0 , "forward": "Direct"}
routingTable.append(routingRow)
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

try:
    thread.start_new_thread( aging_thread, ("Thread-Aging", ) )
except:
    print "Error: unable to start aging thread"

while (True):
    #Do Nothing here just waiting because child threads are doing everything...
    time.sleep(1)
# We might handle some command to print routing table or
