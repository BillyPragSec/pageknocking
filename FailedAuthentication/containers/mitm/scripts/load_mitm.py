"""Entry point for mitmproxy modules.

Modules are loaded according to whether their corresponding environment variable is set to any case variation of 'true'.
"""

import os

# from login import Login
from knocks import Knocks


import database.dbiface as db
from utils.proj_utils import load_config

APP_CONFIG = load_config()
db.init(conn_string=APP_CONFIG["DB"]["SERVER"], db=APP_CONFIG["DB"]["DATABASE"])

addons = []
MODULE_MAPPING = {
    # "LOGIN": Login,
    "KNOCKS": Knocks,
}


def load_modules():
    for env_key, module in MODULE_MAPPING.items():
        try:
            if os.getenv(env_key, "").lower() == "true":
                addons.append(module())
                print(f"Loaded {env_key}")
        except KeyError:
             pass


load_modules()
