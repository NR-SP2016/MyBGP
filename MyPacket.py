import struct
import ctypes
import binascii

KEY_NET = "net"
KEY_SUB = "sub"
KEY_PATH = "path"

def encode(netString, subnString, pathList):
    netArray = encodeAddr(netString)
    subArray = encodeAddr(subnString)
    buf = ctypes.create_string_buffer(4+4+4*len(pathList))
    offset = 0
    struct.pack_into("BBBB", buf, offset, netArray[0], netArray[1], netArray[2], netArray[3])
    offset += 4
    struct.pack_into("BBBB", buf, offset, subArray[0], subArray[1], subArray[2], subArray[3])
    for path in pathList:
        offset += 4
        struct.pack_into("I", buf, offset, path)
    return buf.raw

def decode(rawData):
    if(len(rawData) < 12):
        return -1
    netString = decodeAddr(struct.unpack("BBBB", rawData[0:4]))
    subString = decodeAddr(struct.unpack("BBBB", rawData[4:8]))
    pathList = []
    for i in range(8, len(rawData), 4):
        pathList.append(struct.unpack("=I", rawData[i:i+4])[0])
    return (netString, subString, pathList)

def encodeAddr(addrString):
    addrArray = []
    for addInts in addrString.split("."):
        addrArray.append(int(addInts))
    return addrArray

def decodeAddr(addrArray):
    addrString = ""
    for addString in addrArray:
        addrString += str(addString)
        addrString += "."
    return addrString[:-1]
