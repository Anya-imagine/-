"""
This module provides a centralized place for all imports to avoid circular dependencies.
"""

from .types import FieldType, FieldObject
from .constants import (
    FIELD_TYPE_IP_GHASH,
    FIELD_FLAG_CNT,
    FIELD_FLAG_NODB,
    FIELD_FLAG_DISABLED,
    FIELD_FLAG_IPPRE,
    FIELD_FLAG_FAKE,
    FIELD_TYPE_STR_HASH,
    FIELD_FLAG_FORCE_UTF8,
    FIELD_TYPE_IP,
    FIELD_TYPE_STRING,
    FIELD_FLAG_ECS_CNT,
    FIELD_MAX_JSON_SIZE,
    FIELD_MAX_ELEMENT_SIZE
)
from .session import Session
from .base import ParserInfo

# Import field_manager directly
from .field import field_manager

# Provide lazy loading functions to avoid circular dependencies
def get_dns_module():
    import analyzers.dns
    return analyzers.dns

def get_dhcp_module():
    import analyzers.dhcp
    return analyzers.dhcp

def get_http_module():
    import analyzers.http
    return analyzers.http

def get_icmp_module():
    import analyzers.icmp
    return analyzers.icmp

def get_smb_module():
    import analyzers.smb
    return analyzers.smb

__all__ = [
    'FieldType',
    'FieldObject',
    'FIELD_TYPE_IP_GHASH',
    'FIELD_FLAG_CNT',
    'FIELD_FLAG_NODB',
    'FIELD_FLAG_DISABLED',
    'FIELD_FLAG_IPPRE',
    'FIELD_FLAG_FAKE',
    'FIELD_TYPE_STR_HASH',
    'FIELD_FLAG_FORCE_UTF8',
    'FIELD_TYPE_IP',
    'FIELD_TYPE_STRING',
    'FIELD_FLAG_ECS_CNT',
    'FIELD_MAX_JSON_SIZE',
    'FIELD_MAX_ELEMENT_SIZE',
    'Session',
    'ParserInfo',
    'field_manager',
    'get_dns_module',
    'get_dhcp_module',
    'get_http_module',
    'get_icmp_module',
    'get_smb_module',
] 