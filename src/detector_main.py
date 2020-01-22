'''
Tool that takes a pcap file and SYN/SYN+ACK packet ratio to search for IP addresses
suspected of port scanning attacks. Checks only TCP ethernet packets. 
'''
import argparse

import dpkt

import detector_utils as detector

def run(args):
    pcapFile = open(args['pcapfile'], 'rb')
    pcapReader = dpkt.pcap.Reader(pcapFile)

    ip_flag_dict = detector.create_IP_TCP_flag_dict( pcapReader )
    suspected_scanner_ip_list = detector.create_suspect_IP_list(ip_flag_dict, args['ratio'])
    if len(suspected_scanner_ip_list):
        print('IP addresses likely to be preforming SYN Scan attacks ' \
             f'based on {args["ratio"]} to 1 ratio of SYN to SYN+ACK TCP packets:')
        print (suspected_scanner_ip_list)
    else:
        print ('No SYN scan atttacks detected in TCP/Ethernet packets '  \
              f'for SYN/SYN+ACK ratio of {args["ratio"]}')


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description='syn scan detector for pcap network files')
    arg_parser.add_argument('--pcapfile', nargs='?', default=None, required=True, 
        help='pcap input file required')
    arg_parser.add_argument('--ratio', nargs='?', default=3, required=False, 
        help='ratio of SYNs to SYN+ACKs sent for an IP address to qualify as suspected attacker')
    
    args = vars(arg_parser.parse_args())
    run(args)

