from struct import pack, unpack
from socket import inet_aton, inet_ntoa


def dec2dot(dec):
    '''
    convert ip address from decimal format to dotted-quad format
    '''
    if dec>0xFFFFFFFF:
        dec = 0xFFFFFFFF
    ip = pack('!L', dec)
    return inet_ntoa(ip)

def dot2dec(dot):
    '''
    convert ip address from dotted-quad format to decimal format
    '''
    ip = inet_aton(dot)
    return unpack('!L', ip)[0]

def mac2byte(addr):
    '''
        Convert MAC address to byte
    '''
    mac = []
    byte = ''
    if ':' in addr:
        mac = addr.split(':')
    elif '-' in addr:
        mac = addr.split('-')
    else:
        raise ValueError('error: MAC address not valid')
    for m in mac:
        byte += chr(int(m, 16))
    return byte

def byte2mac(addr):
    '''
        Convert byte mac address to XX:XX:XX:XX:XX:XX
    '''
    mac = ''
    for b in addr:
        byte =  hex(ord(b))    # '0xXX', '0xX'
        byte = byte.replace('x', '')
        
        if len(byte)>2:
            mac += byte[1:] + ':'
        else:
            mac += byte + ':'
    return mac.strip(':')
