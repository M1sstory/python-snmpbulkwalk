#!/usr/bin/env python
#
# Small pure-python library to make snmpbulkwalk request to snmp enabled device and return result
# Only SNMP version 2c supported
#
# Typical usage:
#   from snmpbulkwalk import snmpbulkwalk
#   res = snmpbulkwalk(host, oid, community)
#   # the res will be dict with oid as key and value as value
#   # for integer, counter, gauge & timetick response types value will be type of integer
#   # for string and oid response types value will be string
#   # ipaddr type value returned as string like '127.0.0.1'
#
#   # unprintable string value returns as-is (as nonprintable, NO HEX convertions is done)
#   # for example mac address value will be always returned as 6 bytes string !!!!
#
# This method created primary for internal usage to get data from 1000+ devices every minute
# IT IS not full support of SNMP protocol, it just simple create request packet 
# and make simple unparse of response packet without full support of all answer messsages, 
# no error handling, no full validation of response.
#
# Author: Ivan Zhiltsov (ivan.zhiltsov@pyzzle.ru)
# Created to be used inside www.pyzzle.ru ISP management system


import socket
import struct
import random

SNMP_MAX_REPETITIONS = 10
SNMP_TIMEOUT = 15
SNMP_RECV_BUFFER = 2048

def oid_rawbytes2str(raw_bytes):
    """Decode bytes for packet and return text printable oid value"""
    if not raw_bytes:
        return

    fb = ord(raw_bytes[0])
    oid = '.%s.%s' % (int(fb/40), fb%40)
    skip_next = False
    for idx, i in enumerate(raw_bytes[1:]):
        if skip_next: # allready parsed
            skip_next = False
            continue

        v = ord(i)
        if v<128:
            oid += '.%s' % v
            skip_next = False
        else:
            # idx+2 because we start iteration of second byte and need next byte from current
            oid += '.%s' % ((v-128)*128+ord(raw_bytes[idx+2])) 
            skip_next = True

    return oid

def oid_str2rawbytes(oid):
    """Encode oid to bytes array to use sending packet"""
    if oid.startswith('.'):
        oid = oid[1:]
    oid_splitted = oid.split('.')
    res = ''

    # root items (.1.3 usualy converted to 1 byte chr(43))!
    if len(oid_splitted)>1:
        res+=chr(40*int(oid_splitted[0])+int(oid_splitted[1]))
    # rest items
    for i in oid_splitted[2:]:
        v = int(i)
        if v<128:
            res += chr(v)
        else:
            res += chr(128+int(v/128))
            res += chr(v%128)

    return res


def generate_request_packet(oid, community='public', session_id=123456, request_type='\xa5\x1a'):
    """ Prepare content for udp packet of snmp request.
        Return raw data to be send over udp with snmpbulkwalk request of snmp v2c.

        oid - text field list '.1.3.6.1.2.1.1' no MIB support only numeric value
        community - text field with name of read-only snmp community
        session_id - integer with unique ID of request2
        request_type - raw request type default us for snmpbulkwalk, or may be set to make snmpget
    """


    data = "\x02\x01\x01" # header with out first 2 bytes
                          # (will be inserted at the end with total packet length)

    data += chr(4) # v2c
    data += chr(len(community))
    data += community
    data += request_type # acualy not - but correct 2 raw bytes
    data += chr(2)
    data += chr(4)
    data += struct.pack('!I', session_id) # request ID MUST BE UNIQUE
    data += chr(2)
    data += chr(1)
    data += chr(0)
    data += chr(2)
    data += chr(1)
    data += chr(SNMP_MAX_REPETITIONS) # 10 max-repetitions

    oid_bin = oid_str2rawbytes(oid)
    data += '\x30'
    data += chr(len(oid_bin)+6)
    data += '\x30'
    data += chr(len(oid_bin)+4)
    data += '\x06'
    data += chr(len(oid_bin))
    data += oid_bin
    data += '\x05\x00' # footer

    data = '\x30'+chr(len(data))+data # insert 1 byte and length

    return data

def parse_response_packet(received, community=None, session_id=None):
    """ Parse raw udp response packet
        Return list of tuples with (oid,value)

        received - raw udp packet content to parse
        community and session_id - values from request. 
            if defined method will check that resonse is about this request

        if some thing wrong with packet it will return None
        integer and timeticks returns as integer
        string return as string (even if it is non-printable string.
            !!! HEX-STRING return like snmpwalk is not supported !!!
        oid value return as string like '.1.3.1.x.x.x.'
    """

    if not received:
        return None

    cl = ord(received[8])
    c = received[9:9+cl]
    if community and c!=community:
#        print 'invalid comunity'
        return # invalid community

    sid = received[15+cl:15+cl+4]
    if session_id and sid!=struct.pack('!I', session_id):
#        print 'invalid session_id'
        return # invalid session_id

    status=received[15+cl+4:15+cl+4+6]
    if status!='\x02\x01\x00\x02\x01\x00':
#        print 'response with error message'
        return # response has some error messages
    rest = received[15+cl+4+6+4:]


    result = []

    while rest!='':
        i_l = ord(rest[1])+2
        o_l = ord(rest[3])
        o = rest[4:4+o_l]
        v = rest[4+o_l:i_l]
        oid = oid_rawbytes2str(o)

        if v[0]=='\x04': # string
            value = v[2:]
            result.append((oid, value))
        elif v[0]=='\x06': # oid
            value = '.1.3'
            for i in v[3:]:
                value += '.'+str(ord(i))
            result.append((oid, value))
        elif v[0] in ('\x02', 'C', 'B', 'A', 'F'): # integer, timetick, Gauge32, Counter32, Counter64
            value = 0
            for idx,i in enumerate(reversed(v[2:])):
                 value += pow(256,idx)*ord(i)
            result.append((oid, value))
        elif v[0] == '@': # IP address
            value = '.'.join([str(ord(x)) for x in v[2:]])
            result.append((oid, value))
        elif v[0] == '\x82': # end of mib tag
            pass
        elif v[0] == '\x80': # no such mib tag
            pass
        else:
            # other type
#            print oid
#            print list(v)
            pass # uncomment print it debug failed types and create correct handler for it

        rest = rest[i_l:]

    return result


def snmpbulkwalk(host, oid, community='public', port=161, timeout=None):
    """ Fast execute snmpbulkwalk request
        Return dict with oid as key, value as value

        host - address of snmp device
        oid - requested oid tree
        community - snmp community
        port=161 snmp port
        timeout - socket timeout if not set default value from constant used (15)

        This method perform snmp v2c snmpbulkwalk request, without full support of SNMP protocol.
        It just send request and make simple parse response packet
    """
    if oid[0]!='.': # to support calling with oid like '1.3.1.6.x.x.x' (with out '.' as first char)
        oid = '.' + oid
    res = {}
    addr = (host, port)
    session_id=random.randint(0,pow(2,15))+pow(2,31)
    data = generate_request_packet(oid, community=community, session_id=session_id)
    UDPSock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    UDPSock.settimeout(timeout or SNMP_TIMEOUT)
    try:
        UDPSock.sendto(data,addr)
        received = UDPSock.recv(SNMP_RECV_BUFFER)
    except socket.error:
        received = None
    response = parse_response_packet(received, community=community, session_id=session_id)

    while response:
        if not res and (not response[0][0].startswith(oid) or (response[0][0]!=oid and response[0][0][len(oid)]!='.')):
            # if very-first response in not from our oid tree
            # we for compatibility we need to make snmpget get request for selected oid 
            # (like console net-snmp tool does)

            data = generate_request_packet(oid, community=community, session_id=session_id, request_type='\xa0\x1a')
            UDPSock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            UDPSock.settimeout(timeout or SNMP_TIMEOUT)
            try:
                UDPSock.sendto(data,addr)
                received = UDPSock.recv(SNMP_RECV_BUFFER)
            except socket.error:
                received = None
            response = parse_response_packet(received, community=community, session_id=session_id)

            if not response:
                break

        for c_oid, c_value in response:
            if c_oid.startswith(oid): # add to resulting dictionary only oid from request tree 
                                      # (response may have next items)
                if c_oid==oid or c_oid[len(oid)]=='.': # to avoid false math oid 
                                                       # like '.x.x.10' with request of '.x.x.1'
                    res[c_oid] = c_value


        if response[-1][0].startswith(oid): # if last response oid is still inside oid tree
            session_id += 1
            data = generate_request_packet(response[-1][0], community=community, session_id=session_id)
            try:
                UDPSock.sendto(data, addr)
                received = UDPSock.recv(SNMP_RECV_BUFFER)
            except socket.error:
#                import traceback
#                print "execption", traceback.format_exc()
                received = None
            response = parse_response_packet(received, community=community, session_id=session_id)
        else:
            response = '' # exit from loop

    UDPSock.close()
    return res

if __name__ == "__main__":
    # simple examples of usage
    import sys
    if len(sys.argv)<4:
        print "Usage: %s <host> <community> <oid>" % sys.argv[0]
    else:
        host = sys.argv[1]
        community = sys.argv[2]
        oid = sys.argv[3]
        print "Requesting %s" % oid
        res = snmpbulkwalk(host, oid, community=community)
        for k in sorted(res.keys(), key=(lambda x: '.'.join(["%03d" % int(i) for i in x.split('.') if i]))  ):
            print "           %s : %r" % (k, res[k])
        print "--------------"

