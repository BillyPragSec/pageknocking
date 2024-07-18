import json

from log.type_logger import TypeLogger

import os

try:
    APP_CONFIG_FILE = os.environ["CONFIG_FILE"]
except:
    APP_CONFIG_FILE = "/app/conf/conf.json"

CONFIG = None


def load_config():
    """Loads the application config.

    Returns:
        dict: application config settings
    """
    global CONFIG

    if CONFIG is not None:
        return CONFIG

    with open(APP_CONFIG_FILE) as f:
        CONFIG = json.load(f)
        print("Loaded config file: " + APP_CONFIG_FILE)

    return CONFIG


def init_logger(name, log_type):
    """Initializes a custom JSONL (JSON-lines) logger for various components.

    Args:
        name (str): component name
        log_type (utils.enums.logs_enum.LogsEnum): the component

    Returns:
        TypeLogger: the logger
    """
    return TypeLogger(name, CONFIG["LOG_FILE"], log_type)
