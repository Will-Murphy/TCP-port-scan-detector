# TCP Port Scan Detector:

Takes a PCAP network traffic file as input and a "suspect_ratio", and outputs the ip addresses who are likely to be preforming TCP SYN scan attacks, and who may be preparing further attacks.

## PCAP Analysis:
PCAP analysis for a given IP address in the file is based on ratio of TCP ethernet packets with just the SYN flag sent ,i.e. intiating TCP connection, versus the amount of packets recieving with SYN+ACK flags set, i.e. confirming connection as valid. The higher the ratio, the more likely an IP is to be preforming a "SYN Scan" port scanning attack. The default suspect ratio is set to 3 for a given IP, but can be changed with input arguments

## Set up:
```pip install dpkt```

## Usage: 
cd in **src/**

usage: main --detector.py [-h] --pcapfile [PCAPFILE] [--ratio [RATIO]]

```
syn scan detector for pcap network files
optional arguments:
  -h, --help            show this help message and exit
  --pcapfile [PCAPFILE]
                        pcap input file required
  --ratio [RATIO]       ratio of SYNs to SYN+ACKs sent for an IP address to
                        qualify as suspected attacker
```