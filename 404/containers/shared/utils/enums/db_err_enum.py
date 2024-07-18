from enum import unique

from utils.enums.more_enum import MoreEnum

@unique
class DBErrorsEnum(MoreEnum):

    GENERAL = "GENERAL"
    USER_NOT_FOUND = "USER_NOT_FOUND"
    DEVICE_NOT_FOUND = "DEVICE_NOT_FOUND"
    USER_EXISTS = "USER_EXISTS"
    DEVICE_EXISTS = "DEVICE_EXISTS"
