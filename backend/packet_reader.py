"""Bounded offline PCAP/PCAPNG reader for common link types. Never opens a socket."""
import ipaddress
import struct

class CaptureFormatError(Exception):
    pass

def _u16(b, offset, endian='!'):
    return struct.unpack_from(endian+'H', b, offset)[0]

def _u32(b, offset, endian='!'):
    return struct.unpack_from(endian+'I', b, offset)[0]

def decode(frame, linktype):
    """Return IP/TCP/UDP/ICMP header metadata, or None for unsupported/non-IP frames."""
    try:
        if linktype == 1:  # Ethernet, optional VLAN tags
            if len(frame) < 14: return None
            kind = _u16(frame, 12); offset = 14
            while kind in (0x8100, 0x88a8, 0x9100):
                if len(frame) < offset+4: return None
                kind = _u16(frame, offset+2); offset += 4
        elif linktype == 101:  # raw IP
            offset = 0; kind = 0x0800 if frame and frame[0]>>4 == 4 else 0x86dd
        elif linktype in (113, 276):  # Linux cooked v1/v2
            offset = 16 if linktype == 113 else 20
            if len(frame) < offset: return None
            kind = _u16(frame, 14 if linktype == 113 else 0)
        else:
            return None
        if kind == 0x0800:
            if len(frame) < offset+20 or frame[offset]>>4 != 4: return None
            hlen = (frame[offset]&15)*4
            if hlen < 20 or len(frame) < offset+hlen: return None
            proto = frame[offset+9]
            source = str(ipaddress.IPv4Address(frame[offset+12:offset+16]))
            destination = str(ipaddress.IPv4Address(frame[offset+16:offset+20]))
            fragmented = _u16(frame,offset+6)&0x1fff
            offset += hlen
            if fragmented: proto = -1
        elif kind == 0x86dd:
            if len(frame) < offset+40 or frame[offset]>>4 != 6: return None
            proto = frame[offset+6]
            source = str(ipaddress.IPv6Address(frame[offset+8:offset+24]))
            destination = str(ipaddress.IPv6Address(frame[offset+24:offset+40]))
            offset += 40
            for _ in range(8):
                if proto in (0,43,60):
                    if len(frame)<offset+2:return None
                    next_proto=frame[offset]; length=(frame[offset+1]+1)*8
                    if len(frame)<offset+length:return None
                    proto=next_proto;offset+=length
                elif proto == 44:
                    if len(frame)<offset+8:return None
                    next_proto=frame[offset]; fragment=_u16(frame,offset+2)&0xfff8
                    offset+=8;proto=-1 if fragment else next_proto
                else:break
        else:return None
        result={'source':source,'destination':destination,'protocol':'OTHER','source_port':None,'destination_port':None,'flags':None,'seq':None}
        if proto in (6,17) and len(frame)>=offset+4:
            result['protocol']='TCP' if proto==6 else 'UDP'
            result['source_port']=_u16(frame,offset)
            result['destination_port']=_u16(frame,offset+2)
            if proto==6 and len(frame)>=offset+14:
                result['seq']=_u32(frame,offset+4)
                result['flags']=frame[offset+13]
        elif proto in (1,58):result['protocol']='ICMP'
        return result
    except (ValueError, struct.error, IndexError):
        return None

def read_packets(path):
    """Yield (timestamp or None, raw frame bytes, link type)."""
    with open(path,'rb') as f:
        magic=f.read(4)
        pcap_magics={b'\xd4\xc3\xb2\xa1':('<',1_000_000),b'\xa1\xb2\xc3\xd4':('>',1_000_000),b'\x4d\x3c\xb2\xa1':('<',1_000_000_000),b'\xa1\xb2\x3c\x4d':('>',1_000_000_000)}
        if magic in pcap_magics:
            endian, scale=pcap_magics[magic]
            header=f.read(20)
            if len(header)!=20:raise CaptureFormatError('Truncated PCAP header.')
            linktype=struct.unpack_from(endian+'I',header,16)[0]&0xffff
            while True:
                record=f.read(16)
                if not record:break
                if len(record)!=16:raise CaptureFormatError('Truncated PCAP record header.')
                sec, sub, included, original=struct.unpack(endian+'IIII',record)
                if included>16*1024*1024:raise CaptureFormatError('Packet record exceeds the 16 MiB per-frame safety limit.')
                frame=f.read(included)
                if len(frame)!=included:raise CaptureFormatError('Truncated PCAP packet data.')
                yield sec+sub/scale,frame,linktype
        elif magic==b'\x0a\x0d\x0d\x0a':
            while magic:
                if magic==b'\x0a\x0d\x0d\x0a':
                    raw_length=f.read(4);bom=f.read(4)
                    if len(raw_length)!=4 or len(bom)!=4:raise CaptureFormatError('Truncated PCAPNG section.')
                    endian='<' if bom==b'\x4d\x3c\x2b\x1a' else '>' if bom==b'\x1a\x2b\x3c\x4d' else None
                    if not endian:raise CaptureFormatError('Invalid PCAPNG byte order.')
                    length=struct.unpack(endian+'I',raw_length)[0]
                    if length<28 or length>16*1024*1024:raise CaptureFormatError('Invalid PCAPNG section length.')
                    rest=f.read(length-12)
                    if len(rest)!=length-12 or _u32(rest,len(rest)-4,endian)!=length:raise CaptureFormatError('Truncated PCAPNG section.')
                    interfaces=[]
                else:
                    raw_length=f.read(4)
                    if len(raw_length)!=4:raise CaptureFormatError('Truncated PCAPNG block.')
                    length=struct.unpack(endian+'I',raw_length)[0]
                    if length<12 or length>16*1024*1024:raise CaptureFormatError('Invalid PCAPNG block length.')
                    body=f.read(length-8)
                    if len(body)!=length-8 or _u32(body,len(body)-4,endian)!=length:raise CaptureFormatError('Truncated PCAPNG block.')
                    block_type=struct.unpack(endian+'I',magic)[0]
                    if block_type==1 and len(body)>=12:
                        linktype=_u16(body,0,endian);scale=1_000_000
                        opts=body[8:-4];pos=0
                        while pos+4<=len(opts):
                            code,sz=struct.unpack_from(endian+'HH',opts,pos);pos+=4
                            if code==0:break
                            if code==9 and sz>=1:
                                v=opts[pos];scale=(2 if v&0x80 else 10)**(v&0x7f)
                            pos+=(sz+3)&~3
                        interfaces.append((linktype,scale))
                    elif block_type==6 and len(body)>=24:
                        interface,high,low,included=struct.unpack_from(endian+'IIII',body,0)
                        if interface>=len(interfaces) or included>length-32:raise CaptureFormatError('Invalid PCAPNG packet record.')
                        linktype,scale=interfaces[interface]
                        yield ((high<<32)|low)/scale,body[20:20+included],linktype
                    elif block_type==3 and len(body)>=8 and interfaces:
                        yield None,body[4:4+min(_u32(body,0,endian),len(body)-8)],interfaces[0][0]
                magic=f.read(4)
                if magic and len(magic)!=4:raise CaptureFormatError('Truncated PCAPNG block type.')
        else:
            raise CaptureFormatError('The file header is not a supported PCAP or PCAPNG capture.')
