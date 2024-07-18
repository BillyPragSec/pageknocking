from abc import ABC
import json


class JSONLog(ABC):

    # In Python 3.7, dictionary keys are maintained in order.
    REQUIRED_KEYS = {
        "type": None,
        "timestamp": None,
        "level": None,
        "message": None,
    }

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.__validate()

    def __str__(self):
        return f"{json.dumps(self.kwargs)}"

    def __validate(self):
        _cls = self.__class__
        missing = []
        for key in _cls.REQUIRED_KEYS:
            if key not in self.kwargs:
                missing.append(key)
        if len(missing) > 0:
            raise ValueError(
                f"Instantiated with missing kwargs: {_cls.__name__}, {missing}."
            )

    @property
    def log_type(self):
        return self.kwargs["type"]

    @property
    def timestamp(self):
        return self.kwargs["timestamp"]

    @timestamp.setter
    def timestamp(self, val):
        self.kwargs["timestamp"] = val

    @property
    def level(self):
        return self.kwargs["level"]

    @property
    def message(self):
        return self.kwargs["message"]

    @message.setter
    def message(self, val):
        self.kwargs["message"] = val
