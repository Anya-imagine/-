from scapy.all import *
from ipaddress import ip_address
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
import re

class PacketInfo:
    def __init__(self):
        self.icmp = None
        self.http = None
        self.smb = None
        self.socks = None
        self.ssh = None
        self.tls = None

class Packet:
    def __init__(self):
        self.packet_info = PacketInfo()
        
    def get_http(self, httpinfo):
        self.packet_info.http = httpinfo
    
    def get_icmp(self, icmpinfo):
        self.packet_info.icmp = icmpinfo
    
    def get_smb(self, smbinfo):
        self.packet_info.smb = smbinfo

    def get_socks(self, socksinfo):
        self.packet_info.socks = socksinfo
    
    def get_ssh(self, sshinfo):
        self.packet_info.ssh = sshinfo

    def get_tls(self,tlsinfo):
        self.packet_info.tls = tlsinfo
    
    def get_info(self):
        return self.packet_info




        





