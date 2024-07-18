import json
from datetime import datetime
import os

import database.dbiface as db
import utils.flow_utils as flow_utils
from utils.proj_utils import load_config


class Logging:
    """mitmproxy addon responsible for logging all requests/responses."""

    def __init__(self):
        conf = load_config()
        self.APP = conf["APP"]
        self.TOKEN_UNAME = conf["TOKEN_UNAME"]
        self.TOKEN_SSID = conf["TOKEN_SSID"]
        self.LOGOUT_ELEMENT = conf["LOGOUT_ELEMENT"]
        self.LOGOUT_PATH = conf["LOGOUT_PATH"]
        self.PWDS = conf["PWDS"]
        self.sensor_ip = f"{os.getenv('PROXY_ADDRESS')}:{os.getenv('PROXY_PORT')}"

        self.log_file = "/logs/accesslogs.json"

        print("[Logging] Module enabled")

    def request(self, flow):
        """Handles incoming requests to the web application.

        Args:
            flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow
        """
        session = db.create_session()
        try:
            device_fingerprint = flow_utils.get_device_fingerprint_from_flow(flow)
            device = flow_utils.get_device_from_flow(
                session, self.TOKEN_SSID, flow, device_fingerprint
            )
            logged_in = False
            user = None
            if device is not None:
                user = device.user
            if user is not None:
                logged_in = True

            utc_str = str(datetime.utcnow())
            log_data = {
                "type": "REQUEST",
                "timestamp": utc_str,
                "flow_id": flow.id,
                "http_version": flow.request.http_version,
                "request_method": flow.request.method,
                "request_path": flow.request.path,
                "logged_in": logged_in,
                "origin_user": str(user),
                "origin_ip": eval(str(flow.client_conn.address))[0],
                "request_headers": list(flow.request.headers.items()),
                "request_body": flow.request.text,
                "login_cookie": flow_utils.get_cookie_from_request_headers(
                    self.TOKEN_SSID, flow.request.headers
                ),
                "honeypot_ip": self.sensor_ip,
                "app": self.APP,
            }
            with open(self.log_file, "a") as f:
                f.write(json.dumps(log_data) + "\n")

        except Exception as e:
            print("Exception raised while Logging Request: ", e)
        db.close_session(session)

    def response(self, flow):
        """Handles outgoing responses from the web application.

        Args:
            flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow
        """
        try:
            log_data = {
                "type": "RESPONSE",
                "timestamp": str(datetime.utcnow()),
                "flow_id": flow.id,
                "http_version": flow.request.http_version,
                "request_path": flow.request.path,
                "request_method": flow.request.method,
                "response_code": flow.response.status_code,
                "response_length": len(flow.response.raw_content),
                "response_headers": list(flow.response.headers.items()),
                "origin_ip": eval(str(flow.client_conn.address))[0],
                "login_cookie": flow_utils.get_cookie_from_request_headers(
                    self.TOKEN_SSID, flow.request.headers
                ),
                "honeypot_ip": self.sensor_ip,
                "app": self.APP,
            }
            with open(self.log_file, "a") as f:
                f.write(json.dumps(log_data) + "\n")

        except Exception as e:
            print("Exception raised while Logging Response: ", e)
