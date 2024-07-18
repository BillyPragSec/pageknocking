from enum import unique

from utils.enums.more_enum import MoreEnum

@unique
class ActionsEnum(MoreEnum):

    NONE = "NONE"
    LOGOUT_DEVICE = "LOGOUT_DEVICE"
    LOGOUT_USER = "LOGOUT_USER"
    BAN_DEVICE = "BAN_DEVICE"
    BAN_USER = "BAN_USER"
    TARPIT_DEVICE = "TARPIT_DEVICE"
