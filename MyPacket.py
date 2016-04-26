import struct
import ctypes
import binascii

SIZE_HEADER = 4
SIZE_ADDRESS = 4
SIZE_SUBNET = 4
SIZE_PATH = 4

VALUE_RESERVED = 0

KEY_NET = "net"
KEY_SUB = "sub"
KEY_PATH = "path"

def encode(dataType, netString, subnString, pathList):
    netArray = encodeAddr(netString)
    subArray = encodeAddr(subnString)
    buf = ctypes.create_string_buffer(SIZE_HEADER+SIZE_ADDRESS+SIZE_SUBNET+SIZE_PATH*len(pathList))
    offset = 0
    struct.pack_into("BBBB", buf, offset, dataType, VALUE_RESERVED, VALUE_RESERVED, VALUE_RESERVED)
    offset += 4
    struct.pack_into("BBBB", buf, offset, netArray[0], netArray[1], netArray[2], netArray[3])
    offset += 4
    struct.pack_into("BBBB", buf, offset, subArray[0], subArray[1], subArray[2], subArray[3])
    for path in pathList:
        offset += 4
        struct.pack_into("I", buf, offset, path)
    return buf.raw

def decode(rawData):
    if(len(rawData) < 16):
        return (-1, -1, -1, -1)
    dataType = struct.unpack("B", rawData[0])
    netString = decodeAddr(struct.unpack("BBBB", rawData[4:8]))
    subString = decodeAddr(struct.unpack("BBBB", rawData[8:12]))
    pathList = []
    for i in range(12, len(rawData), 4):
        pathList.append(struct.unpack("=I", rawData[i:i+4])[0])
    return (dataType, netString, subString, pathList)

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
