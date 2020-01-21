import sys 
import socket 
import argparse

import dpkt

def run(args):
    pcapFile = open(args['pcapfile'], 'rb')
    pcapReader = dpkt.pcap.Reader(pcapFile)

    ip_flag_dict = create_IP_TCP_flag_dict( pcapReader )
    suspected_scanner_ip_list = create_suspect_IP_list(ip_flag_dict, args['ratio'])
    if len(suspected_scanner_ip_list):
        print('IP addresses likely to be preforming SYN Scan attacks' \
             f'based on {args["ratio"]} to 1 ratio of SYN to SYN+ACK TCP packets:')
        print (suspected_scanner_ip_list)
    else:
        print ('No SYN scan atttacks detected in TCP/Ethernet packets '  \
              f'for SYN/SYN+ACK ratio of {args["ratio"]}')
    


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
        # Filter for Ethernet Packets
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        # Filter for TCP packets
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue

        tcp = ip.data

        if( (tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK)):
            if ip_flag_dict.get(ip.src) is None: 
                ip_flag_dict[ip.src] = [1,0]
            else: 
                SYN_count = ip_flag_dict[ip.src][0]
                ip_flag_dict[ip.src][0]  = SYN_count+1
        elif( (tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK) ):
            if ip_flag_dict.get(ip.dst) is None: 
                ip_flag_dict[ip.dst] = [0,1]
            else:
                SYN_ACK_count = ip_flag_dict[ip.dst][1]
                ip_flag_dict[ip.dst][1] = SYN_ACK_count+1
    return ip_flag_dict


def create_suspect_IP_list(ip_flag_dict, suspect_ratio): 
    """
    If SYN packet count is more than suspect ratio times greater than
    SYN+ACK count, add ip addr to list of SYN SCAN suspected attackers.
    """
    ip_scanner_list = []
    for ip in ip_flag_dict:
        if ip_flag_dict[ip][0]> suspect_ratio*ip_flag_dict[ip][1] and ip_flag_dict[ip][0]>0:
            ip_scanner_list.append(IP_to_str(ip))
    return ip_scanner_list


def IP_to_str(ip): 
    """ convert ip returned by dpkt to human readable string """
    return socket.inet_ntop(socket.AF_INET, ip)
 

if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description='syn scan detector for pcap network files')
    arg_parser.add_argument('--pcapfile', nargs='?', default=None, required=True, 
        help='pcap input file required')
    arg_parser.add_argument('--ratio', nargs='?', default=3, required=False, 
        help='ratio of SYNs to SYN+ACKs sent for an IP address to qualify as suspected attacker')
    
    args = vars(arg_parser.parse_args())
    run(args)

