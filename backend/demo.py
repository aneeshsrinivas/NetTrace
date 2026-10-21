"""Deterministic synthetic Ethernet/IPv4/TCP captures for demonstration and tests."""
import ipaddress
import struct

def tcp_frame(source, destination, sport, dport, seq, flags=2):
    tcp=struct.pack('!HHIIBBHHH',sport,dport,seq,0,5<<4,flags,4096,0,0)
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),0,0,64,6,0,
                   ipaddress.IPv4Address(source).packed,ipaddress.IPv4Address(destination).packed)
    ethernet=b'\xaa'*6+b'\xbb'*6+struct.pack('!H',0x0800)
    return ethernet+ip+tcp

def write_pcap(path, records, ng=False):
    with open(path,'wb') as f:
        if ng:
            def block(kind,body):
                length=12+len(body)
                f.write(struct.pack('<II',kind,length)+body+struct.pack('<I',length))
            block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))
            block(1,struct.pack('<HHI',1,0,65535))
            for timestamp,frame in records:
                value=int(timestamp*1_000_000)
                pad=b'\0'*((-len(frame))%4)
                block(6,struct.pack('<IIIII',0,value>>32,value&0xffffffff,len(frame),len(frame))+frame+pad)
        else:
            f.write(b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII',2,4,0,0,65535,1))
            for timestamp,frame in records:
                sec=int(timestamp);sub=int((timestamp-sec)*1_000_000)
                f.write(struct.pack('<IIII',sec,sub,len(frame),len(frame))+frame)

def controlled_capture(path):
    import time
    base = time.time() - 120.0
    records=[]
    for i in range(18):
        records.append((base+i*1.5,tcp_frame('10.20.0.14','10.20.0.40',41000+i,20+i,100+i)))
    for i in range(8):
        records.append((base+35+i*2,tcp_frame('10.20.0.14','10.20.0.50',43000+i,443,200+i)))
    write_pcap(path,records)
