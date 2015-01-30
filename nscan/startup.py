import re
import os
import get
import sys
import ConfigParser
from convert import *
from optparse import OptionParser

USAGE = '''
%prog x.x.x.x/x [options]
%prog iface load/unload : Load/Unload Nscan alias interface
%prog resume filename.conf: resume previous scan
'''

help = (
    'Port(s) number (e.g. -p21-25,80)',
    'Threads used to send packets (default=1)',
    'Nscan scripts to import (e.g. --import=ssh_key:22+check_proxy:80-85,8080)',
    'Fetch banners',
    'Number of results to get',
    'Output file',
    'Every N (int) packets sent sleep P (float) (Default=1000,1)')

options = [
    (('-p', '--port'), dict(dest='ports',help=help[0])),
    (('-t', '--threads'), dict(dest='threads',default=1,type=int,help=help[1])),
    (('--import',), dict(dest='imports',help=help[2])),
    (('-b', '--banner'), dict(dest='banner',action="store_true", help=help[3])),
    (('-n',), dict(dest='count', type=int,help=help[4])),
    (('-o', '--output'), dict(dest='output', metavar='FILE', help=help[5])),
    (('-c','--cooldown'), dict(dest='cooldown', default='1000,1', metavar='N,T', help=help[6]))]

class empty(object):
	pass

class Parser(object):
    def __init__(self):
        self.parser = OptionParser(usage=USAGE)
        self.options = empty()
        for args, kwargs in options:
            self.parser.add_option(*args, **kwargs)
    def parse_args(self):
        self.options, args = self.parser.parse_args()
        ifname, ifaddr, ifmac, gateway = get.Network()
        iface = nscanif(ifname, ifaddr)
        if args:
            if 'RESUME' == args[0].upper():
                config = ConfigParser.ConfigParser()
                config.read(args[1])
                self.options = empty()
                self.options.resume = True
                self.options.ifname = ifname
                self.options.siface = ifaddr
                self.options.diface = iface.preloaded()
                self.options.smac = byte2mac(ifmac)
                self.options.dmac = byte2mac(gateway)
                self.options.hosts = eval(config.get('NSCAN', 'hosts'))
                self.options.ports = eval(config.get('NSCAN', 'ports'))
                self.options.threads = eval(config.get('NSCAN', 'threads'))
                self.options.imports = eval(config.get('NSCAN', 'imports'))
                self.options.banner = eval(config.get('NSCAN', 'banner'))
                self.options.count = eval(config.get('NSCAN', 'count'))
                self.options.output = config.get('NSCAN', 'output')
                self.options.indexes = eval(config.get('NSCAN', 'indexes'))
                self.options.cooldown = eval(config.get('NSCAN', 'cooldown'))
            elif 'IFACE' == args[0].upper():
                cmd = args[1].upper()
                if 'LOAD' == cmd:
                    print 'Press enter key to load nscan alias interface'
                    raw_input()
                    siface = iface.load()
                    print 'Nscan alias interface loaded:', siface
                    sys.exit()
                elif 'UNLOAD' == cmd:
                    print 'Press enter key to delete nscan alias interface'
                    raw_input()
                    iface.unload()
                    sys.exit()
                else:
                    self.print_help()
                    sys.exit()
            else:
                self.options.hosts = get.Hosts(args[0])
                self.options.ports = get.Ports(self.options.ports)
                self.options.ifname = ifname
                self.options.siface = ifaddr
                self.options.diface = iface.preloaded()
                self.options.smac = byte2mac(ifmac)
                self.options.dmac = byte2mac(gateway)
                self.options.imports = get.Imports(self.options.imports)
                self.options.cooldown = get.CoolDown(self.options.cooldown)
        else:
            self.print_help()
            sys.exit()
        if not self.options.diface:
            print 'No Nscan alias loaded, try: ./nscan.py iface load'
            sys.exit()
        return self.options
    def print_help(self):
        self.parser.print_help()

class nscanif(object):
    def __init__(self, ifname, ifaddr):
        self.ifname = ifname
        self.ifaddr = dot2dec(ifaddr)
        self.conf = (     
            '\nauto {0}:nscan0\n'
            'allow-hotplug {0}:nscan0\n'
            'iface {0}:nscan0 inet static\n'
            '    address {1}\n'
            '    netmask 255.255.255.0\n')
    def load(self):
        iface = self.preloaded()
        if not iface:
            iface = dec2dot(self.ifaddr+1)
            interfaces = open('/etc/network/interfaces', 'a')
            alias = self.conf.format(self.ifname, iface)
            interfaces.write(alias)
            interfaces.close()
        os.system('service networking restart')  
        return iface
    def unload(self):
        '''
            Delete nscan alias interface
        '''
        interfaces = open('/etc/network/interfaces', 'r')
        content = interfaces.read()
        interfaces.close()
        alias = self.conf.format(self.ifname, '.+?')
        while True:
            entry = re.search(alias, content)
            if entry:
                content = content.replace(entry.group(0), '')
            else:
                break
        interfaces = open('/etc/network/interfaces', 'w')
        interfaces.write(content)
        interfaces.close()
        os.system('service networking restart')
    def preloaded(self):
        '''
            Checks if a nscan interface is pre-loaded
        '''
        interfaces = open('/etc/network/interfaces', 'r')
        content = interfaces.read()
        interfaces.close()
        pattern = self.conf.format(self.ifname, '(.+?)')
        iface = re.search(pattern, content)
        if iface:
            iface = iface.group(1)
        return iface
