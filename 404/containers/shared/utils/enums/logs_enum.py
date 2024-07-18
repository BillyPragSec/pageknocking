from enum import unique

from utils.enums.more_enum import MoreEnum

@unique
class LogsEnum(MoreEnum):
    SYSTEM = "SYSTEM"
    USER_ACTION = "USER_ACTION"
    KNOCK = "KNOCK"
