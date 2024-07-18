from datetime import datetime
import logging

from log.records.system_log import SystemLog
from log.records.user_action_log import UserActionLog
# from log.records.login_log import LoginLog
from log.records.knock_log import KnockLog
from utils.enums.logs_enum import LogsEnum

LOGGING_MAP = {
    LogsEnum.SYSTEM: SystemLog,
    LogsEnum.USER_ACTION: UserActionLog,
    # LogsEnum.LOGIN: LoginLog,
    LogsEnum.KNOCK: KnockLog,
}


class TypeLogger:
    def __init__(self, name, filename, log_type):
        logger = logging.getLogger(name + " [" + log_type.value + "]")
        logger.setLevel(logging.INFO)

        f = open(filename, "a+")
        f.close()

        # Create FileHandler to log to file.
        fh = logging.FileHandler(filename)
        fh.setLevel(logging.INFO)
        logger.addHandler(fh)

        self.logger = logger
        self.log_type = log_type

    def _log(self, fn, log, message, kwargs):
        log.message = message
        log.timestamp = str(datetime.utcnow())
        if kwargs is not None:
            log.kwargs.update(kwargs)
        fn(log)

    def init_log_metadata(self, params):
        return LOGGING_MAP[self.log_type](**params, message=None)

    def debug(self, log, message, **kwargs):
        kwargs.update(
            {
                "level": logging.DEBUG,
            }
        )
        self._log(self.logger.debug, log, message, kwargs)

    def info(self, log, message, **kwargs):
        kwargs.update(
            {
                "level": logging.INFO,
            }
        )
        self._log(self.logger.info, log, message, kwargs)

    def warning(self, log, message, **kwargs):
        kwargs.update(
            {
                "level": logging.WARNING,
            }
        )
        self._log(self.logger.warning, log, message, kwargs)

    def error(self, log, message, **kwargs):
        kwargs.update(
            {
                "level": logging.ERROR,
            }
        )
        self._log(self.logger.error, log, message, kwargs)

    def critical(self, log, message, **kwargs):
        kwargs.update(
            {
                "level": logging.CRITICAL,
            }
        )
        self._log(self.logger.critical, log, message, kwargs)
