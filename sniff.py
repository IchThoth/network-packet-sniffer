import struct
import socket
import textwrap


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def main(): 
    conn = socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(3))
    while True: 
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, sender_mac, ethernet_protocol, data = ethernet_wrap(raw_data)
        print('\nEthernet Frame:')
        print(TAB_1 +'Destination: {}, Source:{}, Protocol:{}',format( dest_mac, sender_mac, ethernet_protocol))

        # 8 means IPv4
        if ethernet_protocol == 8:
            (version, header_length, ttl, protocol, source, target, data) = ipv4_packet_unpack(data)
            print(TAB_1 + 'IPV4 PACKET:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTl: {}',format(version, header_length, ttl))
            print(TAB_2 + 'Protocol:{}, Source: {}, Target: {}', format(protocol, source, target))
            
            # 1 is code for ICMP
            if protocol == 1:
                icmp_type, code, checksum, data = icmp_packet_unpack(data)
                print(TAB_1 + 'ICMP PACKET:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}',format(icmp_type, code, checksum))
                print(TAB_2 + 'Data: ')
                print(format_lines(DATA_TAB_3,data))
            # 6 s code for TCP
            elif protocol == 6:
                (source_port, destination_port,sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment_unpack(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}', format(source_port,destination_port))
                print(TAB_2 + 'Sequence: {},  Acknowledgement: {}', format(sequence,acknowledgement))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH:{}, RST:{}, SYN:{}, FIN:{},', format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data: ')
                print(format_lines(DATA_TAB_3,data))

            # 7 is code for UDP 
            elif protocol == 7:
                source_port, destination_port,length, data = udp_segment_unpack(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}', format(source_port,destination_port,length))

            # support for other internet protocols comes later


#get ethernet frame
#recever 6 bytes -->
#sender 6 bytes --> BROADCAAST ADDRESS = FF:FF:FF:FF:FF:FF                                      {ETHERNET MAC ADDRESSES}
#                   MULTICAST ADDRESS = 01:xx:xx:xx:xx:xx (FIRST ADDRESS BIT = LSB =  ONE!)
#                   
#                   


# Type 2byte --> 0x0800 = IPv4 FRAME
#               0x0806 = ARP REQUEST   {FRAME LENGTH IS NOT USED}
#               0x86DD = IPv6 FRAME 
#
# PAYLOAD (IP/ARP frame + padding) = 46byte - 1500byte
# CRC 6 bytes
                
def ethernet_wrap(data):
    dest_mac_addr,sender_mac_addr, proto = struct.unpack('! 6s 6s H', data[:14])
    return format_mac_addr(dest_mac_addr), format_mac_addr(sender_mac_addr), socket.htons(proto), data[14:] 

#return properly formatted mac address
def format_mac_addr(addr) :
    bytes_str = map('{02x}', format, addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

def ipv4_packet_unpack(data):
    version_header_length = data[0]

    # bit shift the version header by 4
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return version, ttl, proto, format_ipv4(src), format_ipv4(target), data[header_length:]

#i.e 192.162.89.0 this may or may not be my PCs ip address :) 
def format_ipv4(addr):
    return '.'.join(map(str,addr))

# packet data protocol types
#1 ICMP

def icmp_packet_unpack(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_segment_unpack(data):
    (source_port, destination_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8)  >> 3
    flag_rst = (offset_reserved_flags & 4)  >> 2
    flag_syn = (offset_reserved_flags & 2)  >> 1
    flag_fin = offset_reserved_flags & 1
    return source_port, destination_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment_unpack(data):
    source_port, destination_port, size = struct.unpack('! H H 2x H', data[:8])
    return source_port, destination_port, size, data[8:]

def format_lines(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '/n'.join([prefix + line for line in textwrap.wrap(string,size)])



main()