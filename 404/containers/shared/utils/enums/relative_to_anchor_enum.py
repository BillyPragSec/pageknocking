from enum import unique

from utils.enums.more_enum import MoreEnum

@unique
class RelativeToAnchorEnum(MoreEnum):
    TOP_OR_LEFT = "TOP_OR_LEFT" # insert_before
    WITHIN = "WITHIN"   # append
    BOTTOM_OR_RIGHT = "BOTTOM_OR_RIGHT" # insert_after
