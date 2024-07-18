import hashlib
import re
import json

import database.dbiface as db

FILTER_COOKIES = {
    "mycookie",
    "_ga",
} 

def get_ip_from_flow(flow):
    """Retrieves the IP address from the flow.

    Args:
        flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow

    Returns:
        str: IP address
    """
    #print(flow.request.headers)
    #print('Real ip: ', flow.request.headers['X-Real-IP'])
    return str(flow.request.headers['X-Real-IP'])
    #return eval(str(flow.client_conn.address))[0]
    
def get_url_from_flow(flow):
    """ Gets the URL from the Flow """
    return  flow.request.path 

def get_device_fingerprint_from_flow(flow):
    """Retrieves the device fingerprint from the flow. Currently, it uses
    the IP address and the User-Agent in place of an actual fingerprint.

    Args:
        flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow

    Returns:
        str: device fingerprint (hashed)
    """
    ipv6v4 = str(flow.client_conn.address)
    #user_agent = flow.request.headers["User-Agent"]
    fingerprint = f"{ipv6v4}"# {user_agent}"
    return hashlib.sha512(fingerprint.encode()).hexdigest()

def get_device_from_flow(session, token_ssid, flow, device_fingerprint):
    """Retrieves the user from the flow by examining the cookies in the flow request.

    Args:
        session (sqlalchemy.orm.Session): sqlalchemy Session
        token_ssid (str): pattern to match the application cookie name
        flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow
        device_fingerprint (str): device fingerprint

    Returns:
        database.models.Device: Device object
    """
    ss_ids = dict(flow.request._get_cookies())
    #print('Get_device_from_flow - ss_ids: ',ss_ids)
    device = None
    for s in ss_ids.keys():
        if token_ssid in s:
            device = db.get_device(
                session, device_fingerprint=device_fingerprint, ssid=ss_ids[s]
            )
            break
    return device


def get_user_device(session, token_ssid, flow):
    """Retrieves the device and user from the flow by examining cookies in the request.

    Args:
        session (sqlalchemy.orm.Session): sqlalchemy Session
        token_ssid (str): pattern to match the application cookie name
        flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow

    Returns:
        (database.models.Device, database.models.User): Device and User objects
    """
    device_fingerprint = get_device_fingerprint_from_flow(flow)
    device = get_device_from_flow(session, token_ssid, flow, device_fingerprint)
    user = device.user if device is not None else None
    return (device, user)


def get_cookie_from_request_headers(token_ssid, headers):
    """Gets the session cookie from HTTP request headers.

    Args:
        token_ssid (str): pattern to match the application cookie name
        headers (dict): key-value pairs of HTTP headers

    Returns:
        (str, str): cookie name and value for the session
    """
    temp_headers = {k.lower(): v for k, v in headers.items()}
    if "cookie" in temp_headers.keys():
        new_cookie = ""
        new_token = ""
        for kv in re.split(";|,", temp_headers["cookie"]):
            if token_ssid in kv:
                new_token = kv.split("=")[-2].lstrip().rstrip()
                new_cookie = kv.split("=")[-1].lstrip().rstrip()
                return (new_token, new_cookie)
    return ()


def get_cookie_from_response_headers(token_ssid, headers):
    """Gets the session cookie from HTTP response headers.

    Args:
        token_ssid (str): pattern to match the application cookie name
        headers (dict): key-value pairs of HTTP headers

    Returns:
        (str, str): cookie name and value for the session
    """
    temp_headers = {k.lower(): v for k, v in headers.items()}
    cookies = []
    if "set-cookie" in temp_headers.keys():
        new_cookie = ""
        new_token = ""
        for kv in re.split(";|,", temp_headers["set-cookie"]):
            if token_ssid in kv:
                new_token = kv.split("=")[-2].strip()
                new_cookie = kv.split("=")[-1].strip()
                if new_cookie != "delete":
                    cookies.append((new_token, new_cookie))
    if len(cookies) > 0:
        return cookies[-1]
    else:
        return ()


def is_html_request(flow):
    """Checks whether or not the request is an HTML request by examining
    the flow request headers.

    Args:
        flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow

    Returns:
        bool: whether the request is an HTML request
    """
    temp_headers = {k.lower(): v for k, v in flow.request.headers.items()}
    if "accept" in temp_headers.keys():
        return "text/html" in temp_headers["accept"]
    return False


def is_html_response(flow):
    """Checks whether or not the response is an HTML response by examining
    the flow response headers.

    Args:
        flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow

    Returns:
        bool: whether the response is an HTML response
    """
    temp_headers = {k.lower(): v for k, v in flow.response.headers.items()}
    is_html = flow.response.content is not None
    is_html = is_html and "content-type" in temp_headers
    is_html = is_html and "text/html" in temp_headers["content-type"]
    return is_html


def is_css_request(flow):
    """Checks whether the request is a CSS request by examining the
    request headers.

    Args:
        flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow

    Returns:
        bool: whether the request is a CSS request
    """
    temp_headers = {k.lower(): v for k, v in flow.request.headers.items()}
    if "accept" in temp_headers.keys():
        return "text/css" in temp_headers["accept"]
    return False


def is_js_request(flow):
    """Checks whether the request is a JS request by examining the
    request headers.

    Args:
        flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow

    Returns:
        bool: whether the request is a JS request
    """
    temp_headers = {k.lower(): v for k, v in flow.request.headers.items()}
    if "accept" in temp_headers.keys():
        return "application/javascript" in temp_headers["accept"]
    return False


def response_redirect(flow, redirect_url):
    """Mark the response as a redirect to another URL.

    Args:
        flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow
        redirect_url (str): redirected URL
    """
    flow.response.status_code = 301
    flow.response.headers["Location"] = redirect_url


def response_nocache(flow):
    """Sets the response Cache-Control header to 'no-store'.

    Args:
        flow (mitmproxy.flow.Flow): mitmproxy abstraction of a network flow
    """
    flow.response.headers["Cache-Control"] = "no-store"


def load_cookies(cookie_name, cookie_value):
    """
    Load a particular json file containing a list of cookies.
    """
    return [{"name": cookie_name,"value": cookie_value}]



def stringify_cookies(cookies: list):
    """
    Creates a cookie string from a list of cookie dicts.
    """
    return ";".join([f"{c['name']}={c['value']}" for c in cookies])


def parse_cookies(cookie_string: str):
    """
    Parses a cookie string into a list of cookie dicts.
    """
    cookies = []
    for c in cookie_string.split(";"):
        c = c.strip()
        if c:
            k, v = c.split("=", 1)
            cookies.append({"name": k, "value": v})
    return cookies
