from tools import *

def printIPV4(raw_data):
    offset, len, ttl, protocol, src_ip, dst_ip = ipHeader(raw_data[0:20])

    if protocol == 'ICMP':
        newdata = raw_data[offset:offset + 8]
        icmpType, code, id, seq = ICMP(newdata)
        text = f"Protocol: ICMP\nType: {icmpType}\nCode: {code}\nID: {id}\nSeq: {seq}"
    elif protocol == 'TCP':
        data = raw_data[offset:]
        srcPort, dstPort, sqncNum, acknNum, _ = tcpHeader(data)
        text = f"Protocol: TCP\nSrc Port: {srcPort}\nDst Port: {dstPort}\nSeq Number: {sqncNum}\nAck Number: {acknNum}"
    elif protocol == 'UDP':
        data = raw_data[offset:]
        srcPort, dstPort, lenght, checkSum, _ = udpHeader(data)
        text = f"Protocol: UDP\nSrc Port: {srcPort}\nDst Port: {dstPort}\nLenght: {lenght}\nCheckSum: {checkSum}"
    else:
        text = "Unknown Protocol"
    print("<-------------[IPV4 Packet]------------->")
    print(f'Scr IP: {src_ip}')
    print(f'Dst IP: {dst_ip}')
    print(text)
    print("<--------------------------------------->")

if __name__ == '__main__':
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        # read a packet
        raw_buffer = sock.recvfrom(65535)[0]
        dest_mac, src_mac, protocol, data = ethernetFrame(raw_buffer)
        if protocol == 'IPV4':
            printIPV4(data)