from .types import FieldType, FieldObject

class ParserInfo:
    def __init__(self, name, description, version, author):
        self.name = name
        self.description = description
        self.version = version
        self.author = author
        self.parser_func = None
        self.uw = None
        self.parser_save_func = None

class Session:
    def __init__(self):
        self.parser_active = True
        self.tags = []
        self.rules = []
        self.protocols = []
        self.parsers = []
        self.max_fields = 0
        self.mid_save = 0
        self.headers = {'request': {}, 'response': {}}
        self.fields = {} 