from datetime import datetime
import logging

from log.records.json_log import JSONLog
from utils.enums.logs_enum import LogsEnum


class UserActionLog(JSONLog):

    REQUIRED_KEYS = {
        "type": None,
        "timestamp": None,
        "flow_id": None,
        "user": None,
        "device": None,
        "http_version": None,
        "request_path": None,
        "level": None,
        "message": None,
    }

    def __init__(
        self, *, _type=LogsEnum.USER_ACTION, flow, user, device, message, **kwargs
    ):
        """Initializes a UserActionLog instance.

        Args:
            _type (utils.enums.logs_enum.LogsEnum): type of log
            flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow
            user (database.models.User): User object
            device (database.models.Device): Device object
            message (str): log message
            kwargs (dict): kwargs
        """
        user_action_log_data = {
            "type": _type.value,
            "timestamp": str(datetime.utcnow()),
            "flow_id": flow.id,
            "user": user.username,
            "device": device.fingerprint,
            "http_version": flow.request.http_version,
            "request_path": flow.request.path,
            "level": logging.INFO,
            "message": message,
        }
        user_action_log_data.update(kwargs)
        super().__init__(**user_action_log_data)
