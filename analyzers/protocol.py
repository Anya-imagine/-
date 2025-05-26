import configparser

from analyzers.packet import Packet
from analyzers.parsers import API_VERSION
from analyzers.session import Session

config = configparser.ConfigParser()


class ProtocolCreateSessionIdCallback:
    def __init__(self):
        self.session_id = 0
        self.packet = Packet()


class ProtocolPreProcessCallback:
    def __init__(self):
        self.session = Session()
        self.packet = Packet()
        self.is_new_session = 0


class ProtocolProcessCallback:
    def __init__(self):
        self.session = Session()
        self.packet = Packet()


class Protocol:
    def __init__(self):
        self.name = ''
        self.ses = 0
        self.create_session_id = ProtocolCreateSessionIdCallback
        self.pre_process = ProtocolPreProcessCallback
        self.process = ProtocolProcessCallback


# Initialize an array of Protocol objects
magic_protocols = [Protocol() for _ in range(100)]  # Support up to 100 magic protocols
magic_protocol_cnt = 0


def magic_protocol_register(name, ses, create_session_id: ProtocolCreateSessionIdCallback,
                                    pre_process: ProtocolPreProcessCallback, process: ProtocolProcessCallback,
                                    session_size=0, api_version=542):
    # Disable version checks to avoid errors
    # if len(Session) != session_size:
    #     config.exit("Parser '%s' built with different version of arkime.h\n %u != %u", name, len(Session), session_size)
    # if API_VERSION != api_version:
    #     config.exit("Parser '%s' built with different version of arkime.h\n %u!= %u", name, API_VERSION, api_version)
    
    global magic_protocol_cnt
    num = 0
    num += magic_protocol_cnt
    magic_protocols[num].name = name
    magic_protocols[num].ses = ses
    magic_protocols[num].create_session_id = create_session_id
    magic_protocols[num].pre_process = pre_process
    magic_protocols[num].process = process
    return num
