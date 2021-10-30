import struct
import binascii
import socket

def ethernetFrame(raw_data):
    """
    extract Ethernet frame header from raw packet.
    """
    ethernet_header = raw_data[0:14]
    eth_header = struct.unpack('!6s6s2s', ethernet_header)
    dst_mac = getMAC(str(binascii.hexlify(eth_header[0])))
    src_mac = getMAC(str(binascii.hexlify(eth_header[1])))
    packet_type = binascii.hexlify(eth_header[2])
    # ckeck for packet type, full list availavle here -> https://en.wikipedia.org/wiki/EtherType#Values
    if packet_type == b'0800':
        protocol = 'IPV4'
    elif packet_type == b'0806':
        protocol = 'ARP'
    elif packet_type == b'8035':
        protocol = 'RARP'                        
    elif packet_type == b'86dd':
        protocol = 'IPV6'
    else:
        protocol = 'UNKNOWN'
    # return results with rest of the raw packet
    return(dst_mac, src_mac, protocol,raw_data[14:])

def getMAC(mac):
    """
    it will simply turn aabbccddeeff to aa:bb:cc:dd:ee:ff
    """
    s = iter(mac)
    return(':'.join(a+b for a, b in zip(s, s)))

def ipHeader(raw_data):
    """
    parse the ip header from raw packet, we don't need tos, id, offset, sum. you can remove them.
    """
    # '<' is mean storing bytes in little-enidan
    header = struct.unpack('<BBHHHBBH4s4s', raw_data)
    ver = header[0] >> 4
    ihl = (header[0] & 0xF) * 4    # Header Length
    tos = header[1]
    len = header[2]
    id = header[3]
    offset = header[4]
    ttl = header[5]
    protocol_num = header[6]
    sum = header[7]
    src_address = socket.inet_ntoa(header[8])
    dst_address = socket.inet_ntoa(header[9])

    # map protocol constants to their names
    protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    try:
        protocol = protocol_map[protocol_num]
    except Exception as e:
        print('%s No protocol for %s' % (e, protocol_num))
        protocol = str(protocol_num)
    
    return(ihl, len, ttl, protocol, src_address, dst_address)

def ICMP(raw_data):
    """
    Just simply parse ICMP header and return type of ICMP.
    for more understanding take a look at ICMP datagram.
    """
    header = struct.unpack('<BBHHH', raw_data)
    type = header[0]
    code = header[1]
    sum = header[2]
    id = header[3]
    seq = header[4]
    
    type_map = {0: "Echo Reply", 3: "Destination Unreachable", 5: "Redirect Message", 8: "Echo Request"}
    try:
        icmpType = type_map[type]
    except Exception as e:
        print('%s No type for %s' % (e, type))
        icmpType = str(type)

    return(icmpType, code, id, seq)

def tcpHeader(buffer):
    """
    This function is from: https://github.com/O-Luhishi/Python-Packet-Sniffer/blob/f855159c8ceed28191e78b42c58122f5c0bf0d10/Packet-Sniffer.py#L109
    for more understanding take a look at TCP header datagram.
    """
    # 2 unsigned short,2unsigned Int,4 unsigned short. 2byt+2byt+4byt+4byt+2byt+2byt+2byt+2byt==20byts
    packet = struct.unpack("!2H2I4H", buffer[0:20])
    srcPort = packet[0]
    dstPort = packet[1]
    sqncNum = packet[2]
    acknNum = packet[3]
    dataOffset = packet[4] >> 12
    reserved = (packet[4] >> 6) & 0x003F #00001111
    tcpFlags = packet[4] & 0x003F 
    urgFlag = tcpFlags & 0x0020 
    ackFlag = tcpFlags & 0x0010 
    pushFlag = tcpFlags & 0x0008  
    resetFlag = tcpFlags & 0x0004 
    synFlag = tcpFlags & 0x0002 
    finFlag = tcpFlags & 0x0001 
    window = packet[5]
    checkSum = packet[6]
    urgPntr = packet[7]
    # For more print and show, you can uncoment them.
    # if(urgFlag == 32):
    #     print ("\tUrgent Flag: Set")
    # if(ackFlag == 16):
    #     print ("\tAck Flag: Set")
    # if(pushFlag == 8):
    #     print ("\tPush Flag: Set")
    # if(resetFlag == 4):
    #     print ("\tReset Flag: Set")
    # if(synFlag == 2):
    #     print ("\tSyn Flag: Set")
    # if(finFlag == True):
    #     print ("\tFin Flag: Set")

    # print ("\tWindow: "+str(window))
    # print ("\tChecksum: "+str(checkSum))
    # print ("\tUrgent Pointer: "+str(urgPntr))
    # print (" ")

    packet = packet[20:]
    return(srcPort, dstPort, sqncNum, acknNum, packet)

def udpHeader(newPacket):
    """
    this function is from: https://github.com/O-Luhishi/Python-Packet-Sniffer/blob/f855159c8ceed28191e78b42c58122f5c0bf0d10/Packet-Sniffer.py#L160
    for more understanding take a look at UDP header datagram.
    """
    packet = struct.unpack("!4H", newPacket[0:8])
    srcPort = packet[0]
    dstPort = packet[1]
    lenght = packet[2]
    checkSum = packet[3]
    # For more print and show
    # print ("*******************UDP***********************")
    # print ("\tSource Port: "+str(srcPort))
    # print ("\tDestination Port: "+str(dstPort))
    # print ("\tLenght: "+str(lenght))
    # print ("\tChecksum: "+str(checkSum))
    # print (" ")

    packet = packet[8:]
    return(srcPort, dstPort, lenght, checkSum, packet)
