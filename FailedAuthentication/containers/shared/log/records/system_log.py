from datetime import datetime
import logging

from log.records.json_log import JSONLog
from utils.enums.logs_enum import LogsEnum


class SystemLog(JSONLog):

    REQUIRED_KEYS = {
        "type": None,
        "timestamp": None,
        "component": None,
        "level": None,
        "message": None,
    }

    def __init__(self, *, component_type, message):
        """Initializes a SystemLog instance.

        Args:
            component_type (utils.enums.components_enum.ComponentsEnum): component
            message (str): log message
        """
        system_log_data = {
            "type": LogsEnum.SYSTEM.value,
            "timestamp": str(datetime.utcnow()),
            "component": component_type.value,
            "level": logging.INFO,
            "message": message,
        }
        super().__init__(**system_log_data)
