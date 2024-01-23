import struct
import socket
import textwrap




def main(): 
    conn = socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(3))
    while True: 
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, sender_mac, ethernet_protocol, data = ethernet_wrap(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source:{}, Protocol:{}',format( dest_mac, sender_mac, ethernet_protocol))

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

main()