"""
Utility functions for detecting TCP port scanning attacks.
"""
import socket

import dpkt


def create_IP_TCP_flag_dict( pcapReader ):
    """
    produce dictonary of ip addresses and their tcp flag counts as follows    
    {ipaddr : [number of SYN packets sent, number of SYN + ACK packets recieved]} 
    """
    ip_flag_dict = {} 
    for ts, buf in pcapReader:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except: 
            continue
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue

        tcp = ip.data
        # If IP is sending SYN packet, increment SYN count
        if( (tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK)):
            if ip_flag_dict.get(ip.src) is None: 
                ip_flag_dict[ip.src] = [1,0]
            else: 
                ip_flag_dict[ip.src][0] +=1
         # If IP is receiving SYN+ACK packet, increment SYN+ACK count
        elif( (tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK) ):
            if ip_flag_dict.get(ip.dst) is None: 
                ip_flag_dict[ip.dst] = [0,1]
            else:
                ip_flag_dict[ip.dst][1] +=1
    return ip_flag_dict


def create_suspect_IP_list(ip_flag_dict, suspect_ratio): 
    """
    If SYN packet count is more than suspect ratio times greater than
    SYN+ACK count, add ip addr to list of SYN SCAN suspected attackers.
    """
    ip_scanner_list = []
    for ip in ip_flag_dict:
        if ip_flag_dict[ip][0]> suspect_ratio*ip_flag_dict[ip][1] and ip_flag_dict[ip][0]>0:
            ip_scanner_list.append(__IP_to_str(ip))
    return ip_scanner_list


def __IP_to_str(ip): 
    """ convert ip returned by dpkt to human readable string """
    return socket.inet_ntop(socket.AF_INET, ip)