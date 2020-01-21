### SYN Scan detector ### 

Takes a PCAP network traffic file as input, and outputs the ip addresses who are likely to be preforming TCP SYN scan attacks, and who may be preparing further attacks ( based on ratio of packets with just the SYN flag sent ,i.e. intiating TCP connection, versus the amount of packets with SYN+ACK flags set, i.e. confirming connection as valid. )

Note: program only considers packets that has both ethernet and TCP flags set to 1. 

# program syntax: 
python3 detector.py /pcapfilepath/
