# PCapReader
Pcap file reader written in Python.

Each packet is implemented/represented as a multi-level dictionary (similar to scapy's internal implementation) with each layer being the child of the previous layer.

Required dependencies are:
- python 3.x.x
- scapy
- tcpdump

Note: It's recommended that you use virtualenv to install the required packages and run the program. It is also recommend that you use sniff instead of rdpcap() as the former reads packets as needed and doesn't store them in memory. Tcpdump should come installed by default in your distribution. If you want the contents of the packet capture to be written to a file do as follows: `tcpdump -w -i <iface> -c <capture_limit>`, use **any** in place of `<iface>` if you don't want to specify which network interface to read from.

## TODO

* Add more parsing functions
* Improve i/o
* Improve pretty print
