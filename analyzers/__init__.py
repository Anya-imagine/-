#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network protocol analyzer package
"""

# Ensure all modules are properly registered
__all__ = [
    'session',
    'parsers',
    'tls',
    'dns',
    'dhcp',
    'http',
    'icmp',
    'smb',
    'socks',
    'ssh',
    'field',
    'packet_sniffer',
    'protocol',
    'types'
]

# Make sure these modules are properly initialized
from . import session
from . import parsers
from . import field
from . import packet_sniffer
from . import protocol
from . import types

# Import protocol handlers directly instead of using try-except
from . import tls
from . import dns
from . import dhcp
from . import http
from . import icmp
from . import smb
from . import socks
from . import ssh

# Note: http2 module is not present in the file list, so removed from imports
