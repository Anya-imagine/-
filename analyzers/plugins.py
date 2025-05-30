from typing import Optional,Callable,TypeVar,Any
from .base import Session

# 插件常量
PLUGIN_HP_OHC = 1
PLUGIN_HP_OMB = 2
PLUGIN_HP_OMC = 0x00040000

plugins = {}


ArkimeSession = TypeVar('Session')
HTTPParser = TypeVar('HTTPParser')

# 基础插件回调类型
PluginInitFunc = Callable[[], None]
PluginExitFunc = Callable[[], None]
PluginReloadFunc = Callable[[], None]

# 网络数据处理回调
PluginIpFunc = Callable[[Session, Any, int], None]  # ip参数使用Any表示C结构体指针
PluginUdpFunc = Callable[[Session, bytes, int, int], None] 
PluginTcpFunc = Callable[[Session, bytes, int, int], None]

# 会话生命周期回调
PluginSaveFunc = Callable[[Session, int], None]
PluginNewFunc = Callable[[Session], None]

# HTTP解析回调
PluginHttpDataFunc = Callable[[Session, HTTPParser, bytes, int], None]
PluginHttpFunc = Callable[[Session, HTTPParser], None]

# SMTP协议回调
PluginSMTPHeaderFunc = Callable[[Session, bytes, bytes], None]  # 使用bytes处理原始数据
PluginSMTPFunc = Callable[[Session], None]

# 系统状态回调
PluginOutstandingFunc = Callable[[], int]

class Plugin:
    def __init__(self):
        self.p_next = None
        self.p_prev = None
        self.name = None
        self.phash = 0
        p_bucket = 0
        p_count = 0

        num = 0

        ip_func = PluginIpFunc()
        udp_func = PluginUdpFunc()
        tcp_func = PluginTcpFunc()
        pre_save_func = PluginSaveFunc()
        save_func = PluginSaveFunc()
        new_func = PluginNewFunc()
        exit_func = PluginExitFunc()
        reload_func = PluginReloadFunc()
        outstanding_func = PluginOutstandingFunc()

        on_message_begin = PluginHttpFunc() # 初始化响应解析环境
        on_url=PluginHttpDataFunc()
        on_header_field = PluginHttpDataFunc() # 解析头部字段名 
        on_header_field_raw = PluginHttpDataFunc()
        on_header_value = PluginHttpDataFunc() # 解析头部字段值 
        on_headers_complete = PluginHttpFunc() # 头部解析完成
        on_body = PluginHttpDataFunc() # 解析请求体
        on_message_complete = PluginHttpFunc() # 解析完成
        
        smtp_on_header = PluginSMTPHeaderFunc()
        smtp_on_header_complete = PluginSMTPFunc()
        
        

def plugins_callback_http_on_message_begin(session,parser):
    plugin = Plugin()
    for plugin in plugins.values():
        # 双重安全校验:存在属性且为可调用对象
        if hasattr(plugin, 'on_message_begin') and callable(plugin.on_message_begin):
            plugin.on_message_begin(session,parser)

def plugins_callback_http_on_url(session,parser,at,length):
    plugin = Plugin()
    for plugin in plugins.values():
        if hasattr(plugin,'on_url') and callable(plugin.on_url):
            plugin.on_url(session,parser,at,length)

def plugins_callback_http_on_header_field(session,parser,at,length):
    plugin = Plugin()
    for plugin in plugins.values():
        if hasattr(plugin,'on_header_field') and callable(plugin.on_header_field):
            plugin.on_header_field(session,parser,at,length)

def plugins_callback_http_on_header_field_raw(session,parser,at,length):
    plugin = Plugin()
    for plugin in plugins.values():
        if hasattr(plugin,'on_header_field_raw') and callable(plugin.on_header_field_raw):
            plugin.on_header_field_raw(session,parser,at,length)

def plugins_callback_http_on_header_value(session,parser,at,length):
    plugin = Plugin()
    for plugin in plugins.values():
        if hasattr(plugin,'on_header_value') and callable(plugin.on_header_value):
            plugin.on_header_value(session,parser,at,length)

def plugins_callback_http_on_header_complete(session,parser):
    plugin = Plugin()
    for plugin in plugins.values():
        if hasattr(plugin,'on_headers_complete') and callable(plugin.on_headers_complete):
            plugin.on_headers_complete(session,parser)

def plugins_callback_http_on_body(session,parser,at,length):
    plugin = Plugin()
    for plugin in plugins.values():
        if hasattr(plugin,'on_body') and callable(plugin.on_body):
            plugin.on_body(session,parser,at,length)

def plugins_callback_http_on_message_complete(session,parser):
    plugin = Plugin()
    for plugin in plugins.values():
        if hasattr(plugin,'on_message_complete') and callable(plugin.on_message_complete):
            plugin.on_message_complete(session,parser)
            
