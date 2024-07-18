from typing import Iterable, Tuple

from flask import Flask, request
from flask.wrappers import Request
from sqlalchemy.orm.session import Session

import database.dbiface as db
from database.models import User, Device
from utils.enums.components_enum import ComponentsEnum
from utils.enums.logs_enum import LogsEnum
from utils.proj_utils import init_logger, load_config


app = Flask(__name__)

APP_CONFIG = load_config()
LOGGER = init_logger(__name__, LogsEnum.SYSTEM)
API_LOG = LOGGER.init_log_metadata(
    {
        "component_type": ComponentsEnum.API,
    }
)

db.init(conn_string=APP_CONFIG["DB"]["SERVER"], db=APP_CONFIG["DB"]["DATABASE"])


def validate_json_keys(_json: dict, keys: Iterable) -> bool:

    for key in keys:
        if key not in _json:
            return False
    return True


def extract_ssid(request: Request) -> str:

    token_ssid = APP_CONFIG["TOKEN_SSID"]
    ssid = None
    for cookie in request.cookies.keys():
        if isinstance(cookie, str) and cookie.find(token_ssid) == 0:
            ssid = request.cookies[cookie]
            break
    return ssid


def extract_user_info(session: Session, request: Request) -> Tuple[User, str, Device]:

    ssid = extract_ssid(request)
    device = db.get_device(session, ssid=ssid)
    user = device.user if device is not None else None
    username = user.username if user is not None else None
    LOGGER.info(API_LOG, f"found ssid {ssid} user {user} device {device}")
    return (user, username, device)


def get_default_unauthorized_response():
    return "Unauthorized", 401


@app.route("/")
def hello():
    return "Hello from Docker!"


@app.route("/test-auth")
def test_auth():
    with db.managed_session() as session:
        user, username, device = extract_user_info(session, request)
        if device is None:
            return f"Unauthorized, no device", 401
        if user is None:
            return f"Unauthorized, no user", 401
        LOGGER.info(API_LOG, f"{username} hit /test-auth")
        return f"Hi {username}"


@app.route("/test-json", methods=["POST"])
def test_json():
    return request.json
