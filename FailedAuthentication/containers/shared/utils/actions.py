""" A utility for RevProxy that generates HTTPResponses and takes actions on flow instances. """

from mitmproxy import http

import database.dbiface as db
from log.type_logger import TypeLogger
from utils.enums.actions_enum import ActionsEnum
from utils.enums.components_enum import ComponentsEnum
from utils.enums.logs_enum import LogsEnum
import utils.flow_utils as flow_utils
from utils.proj_utils import init_logger


LOGGER = init_logger(__name__, LogsEnum.SYSTEM)
ACTION_LOG = LOGGER.init_log_metadata(
    {
        "component_type": ComponentsEnum.ACTIONS,
    }
)


def response_ban(flow):
    """Generates an HTTP response that indicates the client
    doesn't have permission to access the server resources."""
    flow.response = http.HTTPResponse.make(403, b"", {"Content-Type": "text/plain"})

def response_404(flow):
    flow.response = http.HTTPResponse.make(404, b"", {"Content-Type": "text/plain"})

def response_tarpit(flow, duration=10):
    """Generates an HTTP response that asks the client to
    retry after a certain amount of time.

    Args:
        flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow
        duration (int): duration (in seconds)
    """
    # Re-enable @concurrent decorator or investigate other ways to tarpit.
    # time.sleep(duration)
    # return None
    flow.response = http.HTTPResponse.make(
        102, b"", {"Retry-After": str(duration), "Content-Type": "text/plain"}
    )


def flow_redirect(flow, path):
    """Redirects the flow request path.

    Args:
        flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow
        path (str): redirected path
    """
    flow.request.path = path


def flow_logout_user(flow, user, token_ssid, login_path):
    """Logs out all Devices associated with a User.

    Args:
        flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow
        user (database.models.User): User object
        token_ssid (str): pattern to match the application cookie name
        login_path (str): path of the login page
    """
    for device in user.devices:
        flow_logout_device(flow, device, token_ssid, login_path)


def flow_logout_device(flow, device, token_ssid, login_path):
    """Modifies the flow accordingly to logout the device specified.

    If a logout link has not been specified/configured, then it resorts to
    setting the logout device field to be true and stripping cookies from the
    request. We cannot only ask the client to delete the cookie, assuming
    they are dishonest (i.e., they can ignore the directive and keep using
    the cookie).

    Thus our preferred course of action is to let the application handle
    the request as if it were coming from an unauthenticated client. We
    assume that the application will regularly expire inactive sessions.

    Args:
        flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow
        device (database.models.Device): Device object
        token_ssid (str): pattern to match the application cookie name
        login_path (str): path of the login page
    """
    LOGGER.info(ACTION_LOG, f"flow_logout_device for {device}.")
    # logout_link is updated by the Login addon to be either
    # LOGOUT_ELEMENT or LOGOUT_PATH
    logout_link = device.logout_link
    if len(logout_link) > 0:
        LOGGER.info(
            ACTION_LOG, f"Found logout link for {device}, clicking {logout_link}."
        )
        # print(f"[Actions] Found logout link for {device}, clicking {logout_link}")
        flow.request.path = logout_link
        return

    db.set_logout_device(device, True)
    flow.request.path = login_path

    # option 1, strip cookie on request
    flow_strip_cookies(flow, token_ssid)


def flow_strip_cookies(flow, token_ssid):
    """Strips cookies from the request.

    Args:
        flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow
        device (database.models.Device): Device object
        token_ssid (str): pattern to match the application cookie name
        login_path (str): path of the login page
    """
    if "Cookie" not in flow.request.headers and "cookie" not in flow.request.headers:
        LOGGER.info(ACTION_LOG, f"No cookies found for flow {flow.id}.")
        return

    LOGGER.info(ACTION_LOG, f"Stripping cookies for flow {flow.id}.")
    cookie_header = "Cookie" if "Cookie" in flow.request.headers else "cookie"
    flow.request.headers.pop(cookie_header, None)


def flow_enforce_actions(session, flow, token_ssid):
    """Enforce actions on a specific flow by identifying the user and device and
    checking if any disciplinary actions should be taken.


    Args:
        session (sqlalchemy.orm.Session): sqlalchemy Session
        flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow
        token_ssid (str): pattern to match the application cookie name
    """
    fingerprint = flow_utils.get_device_fingerprint_from_flow(flow)
    device = flow_utils.get_device_from_flow(session, token_ssid, flow, fingerprint)
    if device is None:
        return
    user = device.user
    if user is None:
        return

    # check if there are any disciplinary actions in effect for the user
    if db.is_ban_user(user):
        LOGGER.info(ACTION_LOG, f"ban_user found for {user}.")
        response_ban(flow)
    elif db.is_ban_device(device):
        LOGGER.info(ACTION_LOG, f"ban_device found for {user}, {fingerprint}.")
        response_ban(flow)
    elif db.is_logout_device(device):
        LOGGER.info(ACTION_LOG, f"logout_device found for {user}, {fingerprint}.")
        flow_strip_cookies(flow, token_ssid)


def flow_take_actions(flow, user, device, actions_list, token_ssid, login_path):
    """Modify the response according to the list of actions to take.

    Args:
        flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow
        user (database.models.User): User object
        device (database.models.Device): Device object
        actions_list [(utils.enums.actions_enum.ActionsEnum, int)]: list of actions and their durations
        token_ssid (str): pattern to match the application cookie name
        login_path (str): path of the login page
    """
    for action, duration in actions_list:
        if action == ActionsEnum.LOGOUT_DEVICE.value:
            LOGGER.info(ACTION_LOG, f"Logging out device {device}.")
            flow_logout_device(flow, device, token_ssid, login_path)
        elif action == ActionsEnum.LOGOUT_USER.value:
            LOGGER.info(ACTION_LOG, f"Logging out user {user}.")
            flow_logout_user(flow, user, token_ssid, login_path)
        elif action == ActionsEnum.BAN_DEVICE.value:
            LOGGER.info(ACTION_LOG, f"Banning device {device}.")
            db.ban_device(device, duration)
            response_ban(flow)
        elif action == ActionsEnum.BAN_USER.value:
            LOGGER.info(ACTION_LOG, f"Banning user {user}.")
            db.ban_user(user, duration)
            response_ban(flow)
        elif action == ActionsEnum.TARPIT_DEVICE.value:
            LOGGER.info(ACTION_LOG, f"Tarpitting device {device}.")
            response_tarpit(flow, 10)
