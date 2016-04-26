#!/usr/bin/python
import sys
import socket               # Import socket module
import thread
import time
import MyPacket

#Global constants

PORT_NUM = 57777                # Reserve a port for your service.
INTERVAL = 30

# argv[0] = this program name
# argv[1] = autonomous system
# argv[2] = network inside(Assuming that you have the network...)
# argv[3-20] = ip addresses to neighbors
# example : mybgp.py 60001 192.168.10.0/24 10.0.0.1 10.0.1.2 ...


#Global variables
routingTable = []		# Routing Table!! You might want to save all ip address and AS number mappings



KEY_TYPE_REQUEST = 1
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
        buf = conn.recv(BUFFER_SIZE)
        #d("Received: %s" % ByteToHex(buf))
        recved = len(buf)
        if(recved > 15):
            (dataType, network, subnet, pathVector) = MyPacket.decode(buf)
            if dataType == KEY_TYPE_REQUEST:
                if determineLoop(pathVector):
                    d("Loop detected. Ignoring...")
                    continue
                print "Received: net:%s sub:%s path:%s" %(network, subnet, pathVector)
        if(recved == 0):
            break
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
    d("Connecting to %s..." % neighbor)
    cs.connect((neighbor, PORT_NUM))
    d("Connected to : %s" % neighbor)
    while(True):
        pkt = MyPacket.encode(KEY_TYPE_REQUEST, thisNet, thisSub, [autoSys])
        d("sending:" + ByteToHex(pkt))
        cs.send(pkt)
        time.sleep(INTERVAL)
    cs.close()

def determineLoop(pathVector):
    return autoSys in pathVector

# For the testing for now. It sends its AS number and its network(not real IP. for simulation)
def makePacketTest():
    return "REQ|%s|%s|%s" % (thisNet, thisSub, autoSys)

def usage():
    print "%s <ASNumber> <Network> <Subnet> <LinkIP1> <LinkIP2> ..." %(sys.argv[0])
    print "Example: %s 60001 192.168.10.0 255.255.255.0 10.0.0.1 10.0.1.2 ..." %(sys.argv[0])

# Below is the main function!
if(len(sys.argv) <4):
    usage()
    exit(1)

autoSys = int(sys.argv[1])
thisNet = sys.argv[2]
thisSub = sys.argv[3]
neighbors = sys.argv[4:]
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
