from enum import Enum

class MoreEnum(Enum):

    @classmethod
    def get(cls, val):
        for name, member in cls.__members__.items():
            if name == val:
                return member
        raise ValueError(f"Invalid {cls.__name__} value: {val}.")
    