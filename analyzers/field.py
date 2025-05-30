import configparser
import struct
from enum import Enum
import ipaddress
import logging
from .types import FieldType, FieldObject
from .constants import *
from .session import Session

# Remove circular imports
# from analyzers.dns import dns_hash
from analyzers.rules import rules_run_field_set

config = configparser.ConfigParser()

def hash_find(hash_table, key, key_len):
    # 计算字符串哈希值（模拟 arkime_string_hash_len）
    hash_val = hash(key[:key_len].lower())  # 假设是不区分大小写的哈希

    # 在哈希表中查找对应桶
    bucket = hash_table.get(hash_val, [])

    # 遍历链表查找匹配项（模拟 HASH_FIND_HASH）
    for entry in bucket:
        if entry['len'] == key_len and entry['str'] == key[:key_len]:
            return entry
    return None

class FieldManager:
    def __init__(self):
        self.fields_by_db = {}
        self.fields_by_exp = {}
        self.config = {
            'maxDbField': 0,
            'minInternalField': 1000
        }
        self.logger = logging.getLogger(__name__)

    def field_define(self, *args, **kwargs):
        """
        Define a new field in the system.
        
        Parameters can be provided as positional arguments:
        - group, kind, expression, display_name, es_name, description, field_type, flags, [key, value pairs...]
        
        Or as keyword arguments:
        - group/field_group: The group this field belongs to
        - kind: The field kind (ip, str, int, etc)
        - expression/expr: The expression for this field
        - friendly_name/display_name: Human readable display name
        - db_field/es_name: Database field name
        - help_text/description: Help text for this field
        - field_type: The type of field (from constants)
        - flags: Field flags (from constants)
        - aliases: List of alternative names for this field
        - category: Field category
        - regex: Regular expression for field validation
        
        Returns:
        - Field ID assigned
        """
        # Handle positional arguments
        if len(args) > 0:
            group = args[0]
            kind = args[1] if len(args) > 1 else None
            expression = args[2] if len(args) > 2 else None
            display_name = args[3] if len(args) > 3 else None
            es_name = args[4] if len(args) > 4 else None
            description = args[5] if len(args) > 5 else None
            field_type = args[6] if len(args) > 6 else None
            flags = args[7] if len(args) > 7 else 0
            
            # Handle additional paired arguments
            extra_kwargs = {}
            for i in range(8, len(args), 2):
                if i+1 < len(args):
                    key = args[i]
                    value = args[i+1]
                    extra_kwargs[key] = value
                    
            # Update kwargs with any extra arguments
            kwargs.update(extra_kwargs)
        else:
            # Handle argument aliases from kwargs
            group = kwargs.get('group') or kwargs.get('field_group')
            kind = kwargs.get('kind')
            expression = kwargs.get('expression') or kwargs.get('expr')
            display_name = kwargs.get('friendly_name') or kwargs.get('display_name')
            es_name = kwargs.get('db_field') or kwargs.get('es_name')
            description = kwargs.get('help_text') or kwargs.get('description')
            field_type = kwargs.get('field_type')
            flags = kwargs.get('flags', 0)
        
        if not group or not expression:
            self.logger.error(f"Missing required field parameters: group={group}, expression={expression}")
            return 0
            
        # Generate a field ID
        field_id = self.config['maxDbField'] + 1
        self.config['maxDbField'] = field_id
        
        # Get remaining parameters from kwargs
        aliases = kwargs.get('aliases') 
        category = kwargs.get('category')
        regex = kwargs.get('regex')
        
        # Create field definition
        field_def = {
            'group': group,
            'kind': kind,
            'expression': expression,
            'display_name': display_name,
            'es_name': es_name,
            'description': description,
            'field_type': field_type,
            'flags': flags,
            'aliases': aliases,
            'category': category,
            'regex': regex,
            'field_id': field_id
        }
        
        # Register field by expression
        self.fields_by_exp[expression] = field_def
        
        # Register field by database name
        if es_name:
            self.fields_by_db[es_name] = field_def
            
        # Register field aliases
        if aliases:
            if isinstance(aliases, str):
                # Handle the case where aliases might be a JSON string
                if aliases.startswith("[") and aliases.endswith("]"):
                    import json
                    try:
                        alias_list = json.loads(aliases)
                        for alias in alias_list:
                            if alias and alias not in self.fields_by_exp:
                                self.fields_by_exp[alias] = field_def
                    except:
                        pass
                else:
                    # Single alias as string
                    if aliases not in self.fields_by_exp:
                        self.fields_by_exp[aliases] = field_def
            elif isinstance(aliases, (list, tuple)):
                # List of aliases
                for alias in aliases:
                    if alias and alias not in self.fields_by_exp:
                        self.fields_by_exp[alias] = field_def
        
        # Log field definition
        self.logger.debug(f"Defined field: {expression} (id: {field_id})")
        
        return field_id
        
    def field_by_exp_add_internal(self, exp, field_type, get_cb=None, set_cb=None):
        """
        Add internal callbacks for a field expression
        """
        if exp not in self.fields_by_exp:
            self.logger.warning(f"Adding callbacks for undefined field: {exp}")
            # Create a minimal field definition
            field_id = self.config['minInternalField']
            self.config['minInternalField'] += 1
            
            self.fields_by_exp[exp] = {
                'expression': exp,
                'field_type': field_type,
                'field_id': field_id
            }
        
        field_def = self.fields_by_exp[exp]
        
        if get_cb:
            field_def['get_cb'] = get_cb
            
        if set_cb:
            field_def['set_cb'] = set_cb
            
        return field_def['field_id']

    def field_str_add(self, field_id, session, value, length, is_allocated):
        """添加字符串类型的字段值"""
        print(f"DEBUG: field_str_add called with field_id={field_id}, value={value}, length={length}")  # 调试日志
        
        if not isinstance(session, Session):
            print("DEBUG: Invalid session object")  # 调试日志
            return
        
        if not hasattr(session, 'fields'):
            print("DEBUG: Session has no fields attribute")  # 调试日志
            session.fields = {}
        
        # 获取字段定义
        field_def = None
        for exp, def_info in self.fields_by_exp.items():
            if def_info.get('field_id') == field_id:
                field_def = def_info
                break
        
        if not field_def:
            print(f"DEBUG: No field definition found for field_id={field_id}")  # 调试日志
            return
        
        print(f"DEBUG: Found field definition: {field_def}")  # 调试日志
        
        # 存储字段值
        session.fields[field_id] = value
        session.fields[field_def['expression']] = value
        
        print(f"DEBUG: Added field value: {value}")  # 调试日志
        print(f"DEBUG: Session fields after adding value: {session.fields}")  # 调试日志

    def field_str_add_lower(self, *args, **kwargs):
        """
        Add a string field with lowercase conversion
        """
        # If this is a field update call (session is second argument)
        if len(args) >= 3 and hasattr(args[1], 'add_protocol'):
            field = args[0]
            session = args[1]
            str_val = args[2]
            len_val = args[3] if len(args) > 3 else -1
            copy = args[4] if len(args) > 4 else False
            
            # Convert string to lowercase
            if isinstance(str_val, str):
                lower_val = str_val.lower()
                return self.field_str_add(field, session, lower_val, len(lower_val), copy)
            elif isinstance(str_val, bytes):
                lower_val = str_val.lower()
                return self.field_str_add(field, session, lower_val, len(lower_val), copy)
            return False
        else:
            # For field definition, just delegate to field_str_add
            return self.field_str_add(*args, **kwargs)

    def field_ip4_add(self, *args, **kwargs):
        """
        Add an IPv4 field value or define a new IPv4 field
        """
        # If this is a field update call (session is second argument)
        if len(args) >= 3 and hasattr(args[1], 'add_protocol'):
            field = args[0]
            session = args[1]
            ip_val = args[2]
            
            # Add implementation for field_ip4_add
            # This is a stub - complete implementation should be added
            self.logger.debug(f"field_ip4_add called for field {field} with value {ip_val}")
            return True
        else:
            # For field definition, just delegate to field_define with appropriate defaults
            return self.field_define(
                group=args[0] if len(args) > 0 else None,
                kind="ip",  # Force kind to ip
                expression=args[2] if len(args) > 2 else None,
                display_name=args[3] if len(args) > 3 else None,
                es_name=args[4] if len(args) > 4 else None,
                description=args[5] if len(args) > 5 else None,
                field_type=args[6] if len(args) > 6 else None,
                flags=args[7] if len(args) > 7 else 0,
                # Handle additional paired arguments
                **dict([(args[i], args[i+1]) for i in range(8, len(args), 2) if i+1 < len(args)])
            )

    def field_int_add(self, *args, **kwargs):
        """
        Add an integer field value or define a new integer field
        """
        # If this is a field update call (session is second argument)
        if len(args) >= 3 and hasattr(args[1], 'add_protocol'):
            field = args[0]
            session = args[1]
            int_val = args[2]
            
            # Add implementation for field_int_add
            # This is a stub - complete implementation should be added
            self.logger.debug(f"field_int_add called for field {field} with value {int_val}")
            return True
        else:
            # For field definition, just delegate to field_define with appropriate defaults
            return self.field_define(
                group=args[0] if len(args) > 0 else None,
                kind="integer",  # Force kind to integer
                expression=args[2] if len(args) > 2 else None,
                display_name=args[3] if len(args) > 3 else None,
                es_name=args[4] if len(args) > 4 else None,
                description=args[5] if len(args) > 5 else None,
                field_type=args[6] if len(args) > 6 else None,
                flags=args[7] if len(args) > 7 else 0,
                # Handle additional paired arguments
                **dict([(args[i], args[i+1]) for i in range(8, len(args), 2) if i+1 < len(args)])
            )
            
    def field_mac_oui_add(self, *args, **kwargs):
        """
        Add MAC and OUI field values based on MAC address
        """
        # This method should only be used for field updates
        if len(args) >= 4 and hasattr(args[0], 'add_protocol'):
            session = args[0]
            mac_field = args[1]
            oui_field = args[2]
            mac = args[3]
            
            # Basic implementation - convert MAC to string and add fields
            if isinstance(mac, (bytes, bytearray)):
                mac_str = ':'.join(f'{b:02x}' for b in mac[:6])
                oui_str = ':'.join(f'{b:02x}' for b in mac[:3])
                
                self.field_str_add(mac_field, session, mac_str, len(mac_str))
                self.field_str_add(oui_field, session, oui_str, len(oui_str))
                return True
                
            elif isinstance(mac, str):
                # Assume it's already formatted
                parts = mac.split(':')
                if len(parts) >= 3:
                    oui_str = ':'.join(parts[:3])
                    self.field_str_add(mac_field, session, mac, len(mac))
                    self.field_str_add(oui_field, session, oui_str, len(oui_str))
                    return True
                    
            self.logger.warning(f"Invalid MAC format: {mac}")
            return False
        else:
            self.logger.error("field_mac_oui_add: Invalid arguments")
            return False

    def dns_hash(self, *args):
        # Import dns functions only when needed
        from analyzers.dns import dns_hash
        return dns_hash(*args)

    def field_by_exp(self, expression):
        """
        Get field ID by expression
        """
        if expression in self.fields_by_exp:
            return self.fields_by_exp[expression]['field_id']
        self.logger.warning(f"Field expression not found: {expression}")
        return 0

    # 添加 field_str_get 方法
    def field_str_get(self, field_exp, session):
        """
        获取字段值
        
        参数:
        - field_exp: 字段表达式（如 "tls.version"）
        - session: 会话对象
        
        返回:
        - 字段值，如果不存在则返回空字符串
        """
        print(f"DEBUG: field_str_get called with field_exp={field_exp}")  # 调试日志
        
        if not session or not hasattr(session, 'fields'):
            print(f"DEBUG: Invalid session or no fields attribute")  # 调试日志
            return ""
            
        # 1. 先通过表达式查找字段定义
        field_def = self.fields_by_exp.get(field_exp)
        print(f"DEBUG: field_def={field_def}")  # 调试日志
        
        if not field_def:
            # 如果找不到字段定义，尝试直接从 session.fields 中获取
            value = session.fields.get(field_exp, "")
            print(f"DEBUG: No field_def, trying direct lookup: {value}")  # 调试日志
            return value
            
        # 2. 获取字段ID
        field_id = field_def.get('field_id')
        print(f"DEBUG: field_id={field_id}")  # 调试日志
        
        if not field_id:
            return ""
            
        # 3. 从session中获取字段值 - 优先使用 field_id
        value = session.fields.get(field_id, "")
        print(f"DEBUG: Value from field_id: {value}")  # 调试日志
        
        if not value:
            # 如果通过ID找不到值，尝试通过表达式获取
            value = session.fields.get(field_exp, "")
            print(f"DEBUG: Value from expression: {value}")  # 调试日志
            
        return value

    # ... rest of the class implementation ...

field_manager = FieldManager()
