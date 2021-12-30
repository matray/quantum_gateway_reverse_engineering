import requests
import pprint
import hashlib
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Sessions Number: No more than 5 sessions at a time are allowed. Please wait until open sessions expire.
# Configurable from FIOS Admin Advanced Settings to 15


class Router(object):
    _HEADERS = {"Host": "192.168.1.1",
                "Connection": "keep-alive",
                "Accept": "application/json, text/plain, */*",
                "Origin": "https://192.168.1.1",
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) "
                + "AppleWebKit/537.36 (KHTML, like Gecko) "
                + "Chrome/64.0.3282.140 Safari/537.36",
                "Content-Type": "application/json;charset=UTF-8",
                "Referer": "https://192.168.1.1/",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "en-US,en;q=0.9"}

    @staticmethod
    def content_len_and_str(input_object):
        res_str = json.dumps(input_object)
        return len(res_str), res_str

    def __init__(self, user, password, ip="192.168.1.1"):
        self.user = user
        self.password = password
        self.rsess = requests.Session()
        self.api_base = 'https://{}/api'.format(ip)
        get_api = self.rsess.get(self.api_base, verify=False)
        self.api = get_api.json()

    def login(self):
        pre_pw_to_send = hashlib.sha512()
        pre_pw_to_send.update(
            (self.password + self.api['passwordSalt']).encode('utf-8'))
        pw_to_send = pre_pw_to_send.hexdigest()
        payload = {"password": pw_to_send}
        clen, strpayload = Router.content_len_and_str(payload)
        Router._HEADERS.update({"Content-Length": str(clen)})
        login_res = self.rsess.post(
            self.api_base + "/login", data=strpayload, headers=Router._HEADERS)
        return login_res.status_code == 200

    def logout(self):
        self.rsess.get(self.api_base + '/api/logout', headers=Router._HEADERS)
        self.rsess.close()

    def system(self):
        Router._HEADERS.update(
            {"X-XSRF-TOKEN": self.rsess.cookies.get_dict()["XSRF-TOKEN"]})
        Router._HEADERS.pop("Origin", None)
        Router._HEADERS.pop("Content-Length", None)
        res = self.rsess.get(
            self.api_base + "/settings/system", headers=Router._HEADERS)
        pprint.pprint(res.json())

    def firmware(self):
        Router._HEADERS.update(
            {"X-XSRF-TOKEN": self.rsess.cookies.get_dict()["XSRF-TOKEN"]})
        Router._HEADERS.pop("Origin", None)
        Router._HEADERS.pop("Content-Length", None)
        res = self.rsess.get(self.api_base + "/firmware",
                             headers=Router._HEADERS)
        pprint.pprint(res.json())

    def network(self):
        Router._HEADERS.update(
            {"X-XSRF-TOKEN": self.rsess.cookies.get_dict()["XSRF-TOKEN"]})
        Router._HEADERS.pop("Origin", None)
        Router._HEADERS.pop("Content-Length", None)
        res = self.rsess.get(self.api_base + "/network",
                             headers=Router._HEADERS)
        pprint.pprint(res.json())

    def devices(self):
        Router._HEADERS.update(
            {"X-XSRF-TOKEN": self.rsess.cookies.get_dict()["XSRF-TOKEN"]})
        Router._HEADERS.pop("Origin", None)
        Router._HEADERS.pop("Content-Length", None)
        res = self.rsess.get(self.api_base + "/devices",
                             headers=Router._HEADERS)
        pprint.pprint(res.json())

    def dnsserver(self):
        Router._HEADERS.update(
            {"X-XSRF-TOKEN": self.rsess.cookies.get_dict()["XSRF-TOKEN"]})
        Router._HEADERS.pop("Origin", None)
        Router._HEADERS.pop("Content-Length", None)
        res = self.rsess.get(self.api_base + "/settings/dnsserver",
                             headers=Router._HEADERS)
        # pprint.pprint(res.json())

        jsonResponse = res.json()
        jsonResponse.sort(key=lambda item: item.get("hostname"))
        for i in jsonResponse:
            hn = i['hostname']
            ip = i['ipAddress']
            print(hn+" "+ip)

    def portforward(self):
        Router._HEADERS.update(
            {"X-XSRF-TOKEN": self.rsess.cookies.get_dict()["XSRF-TOKEN"]})
        Router._HEADERS.pop("Origin", None)
        Router._HEADERS.pop("Content-Length", None)
        res = self.rsess.get(self.api_base + "/firewall/portforward",
                             headers=Router._HEADERS)
        pprint.pprint(res.json())
