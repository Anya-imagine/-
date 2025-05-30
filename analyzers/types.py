from enum import Enum

class FieldType(Enum):
    FIELD_TYPE_INT = 0
    FIELD_TYPE_INT_ARRAY = 1
    FIELD_TYPE_INT_HASH = 2
    FIELD_TYPE_INT_GHASH = 3
    FIELD_TYPE_FLOAT = 4
    FIELD_TYPE_FLOAT_ARRAY = 5
    FIELD_TYPE_FLOAT_GHASH = 6
    FIELD_TYPE_STR = 7
    FIELD_TYPE_STR_ARRAY = 8
    FIELD_TYPE_STR_HASH = 9
    FIELD_TYPE_STR_GHASH = 10
    FIELD_TYPE_IP = 11
    FIELD_TYPE_IP_GHASH = 12
    FIELD_TYPE_OBJECT = 13

class FieldObject:
    def __init__(self, ohash=None):
        self.ohash = ohash or {}
        self.fields = {}

    def __str__(self):
        return str(self.ohash)

    def __repr__(self):
        return f"FieldObject({self.ohash})" 