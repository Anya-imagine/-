import configparser
import logging
from datetime import datetime
import threading
from enum import Enum  # Import Enum properly

from _socket import IPPROTO_AH  # Keep this import for compatibility
# Define our own IPPROTO_MAX since it's not available in _socket at runtime
IPPROTO_MAX = 256  # Common value for max IP protocol number

from analyzers.session import Session

config = configparser.ConfigParser()


class PacketReturnCode(Enum):  # Use Enum properly
    PACKET_DO_PROCESS = 0
    PACKET_IP_DROPPED = 1
    PACKET_OVERLOAD_DROPPED = 2
    PACKET_CORRUPT = 3
    PACKET_UNKNOWN = 4
    PACKET_IP_PORT_DROPPED = 5
    PACKET_DONT_PROCESS = 6
    PACKET_DONT_PROCESS_OR_FREE = 7
    PACKET_DUPLICATE_DROPPED = 8
    PACKET_MAX = 9


class Packet:
    def __init__(self):
        self.packet_next = None  # Changed from Packet() to avoid recursive initialization
        self.packet_prev = None  # Changed from Packet() to avoid recursive initialization
        self.ts = datetime.now().timestamp()  # timestamp
        self.packet = 0  # full packet
        self.writer_file_pos = 0  # where in output file
        self.reader_file_pos = 0  # where in input file
        self.writer_file_num = 0  # file number in db
        self.hash = 0  # Saved hash
        self.packet_len = 0  # length of packet
        self.payload_len = 0  # length of ip payload
        self.payload_offset = 0  # offset to ip payload from start
        self.vlan = 0  # non zero if the reader gets the vlan
        self.ip_protocol = 0  # ip protocol
        self.magic_protocol = 0  # arkime protocol
        self.reader_os = 0  # offline - offlineInfo, online - which interface
        self.ether_offset = 11  # offset to current ethernet frame from start
        self.outer_ether_offset = 11  # offset to previous ethernet frame from start
        self.tunnel = 8  # tunnel type
        self.direction = 1  # direction of packet
        self.v6 = 1  # v6 or not
        self.outer_v6 = 1  # outer v6 or not
        self.copied = 1  # don't need to copy
        self.was_fragment = 1  # was a fragment
        self.ip_offset = 11  # offset to ip header from start
        self.outer_ip_offset = 11  # offset to outer ip header from start
        self.vni = 24


class PacketHead:
    def __init__(self):
        self.packet_next = None
        self.packet_prev = None
        self.lock = threading.Lock()
        self.cond = threading.Condition(self.lock)


class PacketBatch:
    def __init__(self):
        self.packet_queue = []
        self.count = 0
        self.reader_pos = 0


class PacketEnqueueCallback:
    def __init__(self):
        self.batch = PacketBatch()
        self.packet = Packet()
        self.data = None
        self.length = 0


ip_callbacks = []  # Changed to list to avoid initialization errors
for i in range(IPPROTO_MAX):
    ip_callbacks.append(None)  # Fill with None


def packet_set_ip_callback(type, enqueue_callback):
    if type >= IPPROTO_MAX:  # Now using our defined IPPROTO_MAX
        logging.error("ERROR - type value too large %d", type)
    else:
        ip_callbacks[type] = enqueue_callback

