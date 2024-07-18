from datetime import datetime, timedelta

from bs4 import BeautifulSoup
import pytz
import json
import os
from datetime import datetime

from mitmproxy import http

import database.dbiface as db
import utils.actions as actions
import utils.constants as constants
from utils.enums.actions_enum import ActionsEnum
from utils.enums.components_enum import ComponentsEnum
from utils.enums.logs_enum import LogsEnum
import utils.flow_utils as flow_utils
from utils.proj_utils import load_config, init_logger


class Knocks:
    def __init__(self):
        conf = load_config()
        self.DOMAIN = conf["DOMAIN"]
        self.TOKEN_SSID = conf["TOKEN_SSID"]
        self.LOGIN_PATH = conf["LOGIN_PATH"]
        self.WHITELISTED = conf["WHITELISTED"]
        self.WHITELISTED_FILE_EXT = conf["WHITELISTED_FILE_EXT"]
        self.WHITELISTED_QUERY_KEY = conf["WHITELISTED_QUERY_KEY"]
        self.BLACKLISTED = conf["BLACKLISTED"]
        self.FOLLOWUP_TIMEOUT = conf["FOLLOWUP_TIMEOUT"]
        self.FOLLOWUP_SCRAPE_TAGS = conf["FOLLOWUP_SCRAPE_TAGS"]
        self.TIMEZONE = conf["TIMEZONE"]
        self.PWDS = conf["PWDS"]

        self.REVPROXY_LOGS = conf["LOG_FILE"]

        self.system_logger = init_logger(__name__, LogsEnum.SYSTEM)
        self.knock_logger = init_logger(__name__, LogsEnum.KNOCK)
        self.base_system_log = self.system_logger.init_log_metadata(
            {
                "component_type": ComponentsEnum.KNOCK,
            }
        )
        self.pre_authentication_requests = {}
        self.knock_dict = {}
        self.requests_last_10_min = {}

        self.system_logger.info(self.base_system_log, "Module enabled.")

    def request(self, flow):
        with db.managed_session() as session:

            if 'clear_out_knock_dictionary' in flow.request.path:
                self.knock_dict.clear()
                #print('Knock_dict: ', self.knock_dict)
                self.requests_last_10_min.clear()
                #print('Requests in last 10 min: ', self.requests_last_10_min)

            self.cookie_update_on_knock(session, flow)
            # Wrong credentials ---------------------------------------------------------------------------
            
            if flow.request.method == "POST":
                #print('This is a POST method.')
                if not self.check_knocks(session):
                    #print('This should redirect to the Wrong Credentials')
                    if flow.request.urlencoded_form:
                        #print(flow.request.urlencoded_form)
                        flow.request.urlencoded_form["pwd"] = "admin"
               
            # Safety net for all credential post
            if flow.request.method == "POST":
                #print('Safety net engaged')
                if flow.request.urlencoded_form:
                    #print(flow.request.urlencoded_form)
                    flow.request.urlencoded_form["pwd"] = "admin"
            
              

    def response(self, flow):
        with db.managed_session() as session:
            user, device = self.update_on_knock(session, flow)
            # 404 redirection
            # if 'wp-admin' in str(flow.request.path) or 'wp-login' in str(flow.request.path) or 'author' in str(flow.request.path) or 'xmlrpc' in str(flow.request.path) or flow.request.method =="HEAD":
            #     #print("Found login page request")
            #     if not self.check_knocks(session, flow):
            #         #print('This should redirect to the 404')
            #         #redirect404 = '/'#'http://proxy_address_to_change'+str(self.DOMAIN)
            #         #actions.flow_redirect(flow, redirect404)
            #         flow.response.status_code = 404
            #         flow.response = http.HTTPResponse.make(404, b"404 - Page Not Found",{"Content-Type": "text/plain"})

            '''
            # grab cookies from the request and response
            res_cookie = flow_utils.get_cookie_from_response_headers(
                'wordpress_test_cookie', dict(flow.response.headers)
            )
            #print('Cookie res: ', res_cookie)
            # check if there is a pending login for the current flow and there is a login cookie from the response
            if flow.id in self.pre_authentication_requests.keys() and len(res_cookie) > 0:
                #print("Successful login for flow: ", flow.id,' \n')
                #print("Cookies from response: ", res_cookie,' \n')
                #print("Flow request: ", flow.request.pretty_url, ' \n')

                user_info = self.pre_authentication_requests.pop(flow.id)
                user_identifier = user_info["user_identifier"]
                fingerprint = user_info["fingerprint"]
                ip = user_info["ip"]

                #print("User identifier: ", user_identifier,' \n')
                #print("Fingerprint: ", fingerprint,' \n')
                #print("IP: ", ip, ' \n')
            else:
                req_cookie = flow_utils.get_cookie_from_request_headers(
                    'wordpress_test_cookie', dict(flow.request.headers)
                )
                #print('Cookie req: ', req_cookie)
                if (
                    len(req_cookie) > 0
                    and len(res_cookie) > 0
                    and res_cookie[1] != req_cookie[1]
                ):
                   
                    session_id = res_cookie[1]
                    #print('Seesion id: ', session_id)
            
            device, user = flow_utils.get_user_device(session, 'wordpress', flow)
            
            
            if device is None or user is None:
                return
            base_knock_log = self.knock_logger.init_log_metadata(
                {
                    "flow": flow,
                    "user": user,
                    "device": device,
                    "pageknock_path": flow.request.path,
                    "action_taken": ActionsEnum.NONE,
                }
            )
            self.knock_logger.info(
                    {
                    "flow": flow,
                    "user": user,
                    "device": device,
                    "pageknock_path": flow.request.path,
                    "action_taken": ActionsEnum.NONE,
                }
                )
            '''

    def compare_knocks(self, def_knocks, try_knocks, flow):
        ips = list(try_knocks.keys())
        for i in range(len(list(try_knocks.values()))):
            if ips[i] in flow_utils.get_ip_from_flow(flow):
                #print('Inside first for loop')
                try_knocks = list(try_knocks.values())[i]['pageknock_path']
                #print(try_knocks)
                bool_existence = False
                bool_order = False
                # 1. Check that all instances are in
                common_appearring_knocks = []
                for try_knock in try_knocks:
                    if try_knock in def_knocks:
                        common_appearring_knocks.append(try_knock)
                # 2. Check correct order of knock sequence (sublist in common appearing knocks)
                sublist_existence = any(common_appearring_knocks[i : i + len(def_knocks)] == def_knocks for i in range(len(common_appearring_knocks)-len(def_knocks)+1))
                if sublist_existence:
                    #print('IP: ', ips[i], ' has cleared the pageknocks.')
                    self.system_logger.info(self.base_system_log, f"IP {ips[i]} has cleared the knocks")
                    return True
                #print('IP: ', ips[i], ' has NOT cleared the pageknocks.')
                return False
            
        
    def append_to_nested_value_list(self, dictionary, key1, key2, value):
        if key1 not in dictionary:
            dictionary[key1] = {}
        if key2 not in dictionary[key1]:
            dictionary[key1][key2] = list()
        dictionary[key1][key2].append(value)
        return dictionary

    def check_knocks(self, session, flow):

        #print("Detected user ",user,"-",device," request ",url,".")

        # 1. Recover default user knocking sequence from db ----------------------------------------------------------------------------------
        #knock_from_db = db.get_knock_from_user(session, device.user)
        #knock_sequence = knock_from_db.knock_sequence
        # String handling
        #knock_sequence = str(knock_sequence).replace('\"','').replace("\'",'').replace('[','').replace(']','').split(',')
        #for ks in knock_sequence:
        #    #print('Knock: ',ks)
        
        # 1.1 Instead of passing throught the db, we take the default knocks directly
        admin_default_knocks = os.environ["ADMIN_DEF_KNOCKING_SEQUENCE"]
        knock_sequence = []
        with open(admin_default_knocks,'r') as admin_def_pk_file:
            for line in admin_def_pk_file.readlines():
                for req in line.split(','):
                    knock_sequence.append(req)
        #print('Admin default knock sequence: ', knock_sequence)
        
        #print(f'The given knocking sequence for user {device.user} is {knock_sequence}')


        # 2. Load web app sitemap paths to list  --------------------------------------------------------------------------------------
        sitemap = []
        sitemap_file_address = os.environ["SITEMAP"]
        with open(sitemap_file_address,'r') as sitemap_file:
            for line in sitemap_file.readlines():
                sitemap.append(line[:-1])
        #print(sitemap)

        # 3. Recover user page knocks from logs --------------------------------------------------------------------------------------
        '''
        logs = []
        logs_address = self.REVPROXY_LOGS
        with open(logs_address,'r') as logs_file:
            json_list = list(logs_file)
            for json_str in json_list:
                logs.append(json.loads(json_str))
        '''
        #print(logs)
        # user,device,timestamp,request_path
        reqs = []
        if not self.knock_dict:
            return False
        for flow_id in self.knock_dict.keys():
            reqs.append([self.knock_dict[flow_id]['ip'],self.knock_dict[flow_id]['timestamp'],self.knock_dict[flow_id]['request_path']])

        # Only keep the requests included in the sitemap that have been made by the given ip in the last 10 mins
        if not reqs:
            return False
        self.requests_last_10_min.clear()
        for i in range(len(reqs)):
            #print('Requests after dict change: ',reqs[i])
            #request_timestamp = datetime.strptime(reqs[i][1], '%Y-%m-%d %H:%M:%S.%f')
            request_timestamp = datetime.utcfromtimestamp(reqs[i][1])
            url_path = 'http://'+str(self.DOMAIN)+reqs[i][2]
            if abs(int((datetime.utcnow()-request_timestamp).total_seconds()))<300 and url_path in sitemap:
                if reqs[i][0] in self.requests_last_10_min and "timestamp" in self.requests_last_10_min[reqs[i][0]] and str(request_timestamp) in self.requests_last_10_min[reqs[i][0]]["timestamp"]:
                    continue
                self.requests_last_10_min = self.append_to_nested_value_list(self.requests_last_10_min, reqs[i][0], "timestamp", str(request_timestamp))
                self.requests_last_10_min = self.append_to_nested_value_list(self.requests_last_10_min, reqs[i][0], "pageknock_path", url_path)
                #self.requests_last_10_min[reqs[i][2]]={"timestamp":str(request_timestamp),"pageknock_path":url_path}
            #print('Requests included in the sitemap that have been made in the last 10 minss',user,'---', self.requests_last_10_min)
        #print('The knock sequence for user ',user,' is correct: ',self.compare_knocks(knock_sequence,self.requests_last_10_min))
        return self.compare_knocks(knock_sequence,self.requests_last_10_min, flow)

    def cookie_update_on_knock(self, session, flow):
        #if flow.request.method == "GET":
        user_identifier = 'kn'
        fingerprint = flow_utils.get_device_fingerprint_from_flow(flow)
        ip = flow_utils.get_ip_from_flow(flow)

        self.pre_authentication_requests[flow.id] = {
            "user_identifier": user_identifier,
            "fingerprint": fingerprint,
            "ip": ip,
            "request_path": flow.request.path,
        }

        
        """Add a specific set of cookies to every request."""
        # obtain any cookies from the request
        _req_cookies_str = flow.request.headers.get("cookie", "")
        req_cookies = flow_utils.parse_cookies(_req_cookies_str)

        # add our cookies to the original cookies from the request
        all_cookies = req_cookies + flow_utils.load_cookies(str(user_identifier),str(fingerprint))

        # modify the request with the combined cookies
        flow.request.headers["cookie"] = flow_utils.stringify_cookies(all_cookies)
        #print('Cookies from request: ',flow.request.headers.get("cookie", ""))

    def update_on_knock(self, session, flow):
        # grab cookies from the request
        user = None
        device = None
        res_cookie = flow_utils.get_cookie_from_request_headers('kn', dict(flow.request.headers))
        #print("Request headers in list form: ", list(flow.request.headers.items()))

        #print("Flow id: ", flow.id, " ------ res_cookie: ", res_cookie)
        if flow.id in self.pre_authentication_requests.keys():# and len(res_cookie) > 0:

            #print("Knock for flow: ", flow.id)
            #print("Cookies from response: ", res_cookie)    
            #print("Flow request: ",flow.request.pretty_url)
            
            user_info = self.pre_authentication_requests.pop(flow.id)
            user_identifier = user_info["user_identifier"]
            fingerprint = user_info["fingerprint"]
            ip = user_info["ip"]

            user = db.get_user_by_name(session, user_info["user_identifier"])
            if user is None:
                #print("Creating new user: ",user_identifier)
                user = db.create_new_user(session, user_identifier)
                db.add_default_knocking_sequence(user)

            device = db.get_device(session, device_fingerprint=fingerprint, user_id=user.id)
            if device is None:
                #print("Creating new device for user: ", user," with fingerprint: ",fingerprint)
                device = db.create_new_device(session, user, fingerprint, ip=ip)

            device.session_key = res_cookie[0]
            device.session_id = res_cookie[1]

            self.knock_dict[flow.id] ={
                "ip": flow_utils.get_ip_from_flow(flow),
                "timestamp": flow.request.timestamp_start,
                "request_path": flow.request.path,

            }

            base_knock_log = self.knock_logger.init_log_metadata(
                {
                    "flow": flow,
                    "user": user,
                    "device": device,
                    "ip": flow_utils.get_ip_from_flow(flow),
                    "pageknock_path": flow.request.path,
                    "action_taken": ActionsEnum.NONE,
                }
            )
            self.knock_logger.info(log=base_knock_log, message=f"Added knock: user {user} and device {device} - Knock path: {flow.request.path} - Flow {flow}")
            
        return user, device
