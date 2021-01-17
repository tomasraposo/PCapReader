from scapy.all import *
from scapy.layers.inet import IP, TCP
from io import StringIO
import os
import re

class Colour:
    BLUE = "\033[94M"
    GREEN = "\033[32m"
    RED = "\033[91m"
    WHITE = "\033[0m"
    
class PCapReader:    
    def __init__(self, pkts):
        self.http_methods = ["GET", "POST"]
        self.pkts = self._parse_pkts(pkts)
    
    def _parse_pkts(self, pkts):
        rexp = re.compile("\|*?#+[A-Za-z0-9]*#+")
        pkts_list = []
        ptr = None
        for pkt in pkts:
            hmap = {}
            _stdout, buff = self._redirect_stdout()
            pkt.show()
            self._fix_stdout(_stdout)
            ptr = hmap
            for st in buff.getvalue().split('\n'):
                if bool(rexp.match(st)):
                    key = self._parse_key(st)
                    ptr[key] = {}
                    ptr = ptr[key]
                else:
                    try:
                        k,v = self._parse_val(st)
                        if self.http_methods[0] in v:
                            v = self._parse_get(v)
                    except (ValueError):
                        pass
                    else:
                        ptr[k] = v
            pkts_list.append(hmap)
        return pkts_list
                   
    def _parse_key(self, key):
        return ''.join(c for c in key if c.isalpha() or c.isspace())

    def _parse_val(self, val):
        return tuple(map(lambda x: x.strip(), val.split("=")))      
  
    def _parse_get(self, val):
        val=val.strip("'")
        return re.sub(r"(\b\\+r)+", " ", val, 0)

    def _redirect_stdout(self):
        buff = StringIO()
        _stdout = os.sys.stdout
        os.sys.stdout = buff
        return (_stdout, buff)

    def _fix_stdout(self, _stdout):   
        os.sys.stdout = _stdout
        
    def get_num_of_packets(self):
        return len(self.pkts)
                                    
    def has_layer(self,pkt,layer):
        for k,v in pkt.items():
            if k == layer:
                return (True, v)
            elif type(v) is dict:
                return self.has_layer(v,layer)
        return (False, None)
    
    def get_pkts(self):
        return self.pkts
       
    def show(self, pkt):
        level_cnt = 1
        def pprint(_hmap = pkt, kpadding=" "):
            nonlocal level_cnt
            for k, v in _hmap.items():
                if type(v) is dict:
                    print(f"\n{kpadding[:level_cnt*2]}{Colour.GREEN}{k} : {{")
                    level_cnt+=1
                    kpadding*=2
                    pprint(v, kpadding)
                else:
                    print(f"{kpadding[:level_cnt*2]}{Colour.WHITE}{k} : {Colour.RED}{v}")
        pprint(pkt)
        kpadding=" "*2*level_cnt
        for i in range(1, level_cnt):
            print(f"{kpadding[:level_cnt*2]}{Colour.GREEN}}}")
            level_cnt-=1



    
if __name__ == "__main__":
    if len(os.sys.argv) < 2:
        print("Usage: python3 PcapReader.py [pcap]")
        os.sys.exit()
    
    preader = PCapReader(sniff(offline=os.sys.argv[1]))
    
    for pkt in preader.get_pkts():
        reader.show(pkt)
