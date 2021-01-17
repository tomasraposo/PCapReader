# PCapReader
Pcap file reader written in Python.

Each packet is implemented/represented as a multi-level dictionary (similar to scapy's internal implementation) with each layer being the child of the previous layer.

* Required dependencies are:
- python 3.x.x
- scapy
- tcpdump

Note: It's recommended that you use virtualenv to install the required packages and run the program. It is also recommend that you use sniff instead of rdpcap() as the former reads packets as needed and doesn't store them in memory.
