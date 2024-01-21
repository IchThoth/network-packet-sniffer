import struct
import socket
import textwrap

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
                
def ethernet_wrap(data):
    dest_mac_addr,sender_mac_addr, proto = struct.unpack('! 6s 6s H', data[:14])
    return format_mac_addr(dest_mac_addr), format_mac_addr(sender_mac_addr), socket.htons(proto), data[14:] 

#return properly formatted mac address
def format_mac_addr(addr) :
    bytes_str = map('{02x}', format, addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr



