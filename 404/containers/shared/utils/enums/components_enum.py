from enum import unique

from utils.enums.more_enum import MoreEnum

@unique
class ComponentsEnum(MoreEnum):
    ACTIONS = "ACTIONS"
    API = "API"
    DB = "DB"
    MITM_PROXY = "MITM_PROXY"
    KNOCK = "KNOCK"
