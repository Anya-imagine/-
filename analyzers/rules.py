import configparser
from typing import Optional

from analyzers import BSB

config = configparser.ConfigParser()

class Rule:
    def __init__(self, name, condition, action):
        self.file_name = None
        self.name = name
        self.bpf = None
        self.bpfp = Optional['bpf_program'] = None
        self.hash = []
        self.hash_not = []
        self.match = []
        self.tree4 = []
        self.tree6 = []
        self.ops = Optional['Field_ops'] = None
        self.matched = 0
        self.fields = 0
        self.fields_len = 0
        self.fields_not_len = 0
        self.save_flags = 0
        self.log = 0
        self.set_rule = 0

def rules_check_rule_fields(session, rule,skip_pos, log_str:BSB):
    pass

def rules_run_field_set(session, field, value):
    """规则触发占位函数（等待后续实现）"""
    pass

def rules_run_after_classify(session):
    pass

def yara_execute(session, data, remaining, which):
    pass
