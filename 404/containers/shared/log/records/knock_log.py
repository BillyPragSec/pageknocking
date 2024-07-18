import copy
from datetime import datetime

from log.records.user_action_log import UserActionLog
from utils.enums.logs_enum import LogsEnum


class KnockLog(UserActionLog):

    REQUIRED_KEYS = copy.copy(UserActionLog.REQUIRED_KEYS)
    REQUIRED_KEYS.update(
        {
            "pageknock_path": None,  # longest prefix match
            #"knock_sequence_compliance": None,
            "action_taken": None,
        }
    )

    def __init__(self, *, flow, user, device, ip, pageknock_path, action_taken, message):
        """Initializes a KnockLog instance.

        Args:
            flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow
            user (database.models.User): User object
            device (database.models.Device): Device object
            pageknock_path (str): path that the request matched
            action_taken (utils.enums.actions_enum.ActionsEnum): action taken
            message (str): log message
        """
        user_action_log_data = {
            "_type": LogsEnum.KNOCK,
            "flow": flow,
            "user": user,
            "device": device,
            "ip":ip,
            "message": message,
        }
        knock_log_data = {
            "pageknock_path": pageknock_path,
            "action_taken": action_taken.value,
        }
        super().__init__(**user_action_log_data, **knock_log_data)
