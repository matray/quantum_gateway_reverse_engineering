import requests
import pprint
import hashlib
import json

_HEADERS = {"Host": "192.168.1.1",
"Connection": "keep-alive",
"Accept": "application/json, text/plain, */*",
"Origin": "http://192.168.1.1",
"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36",
"Content-Type": "application/json;charset=UTF-8",
"Referer": "http://192.168.1.1/",
"Accept-Encoding": "gzip, deflate",
"Accept-Language": "en-US,en;q=0.9"}

def _content_len_and_str(input_object):
	res_str = json.dumps(input_object)
	return len(res_str), res_str	

class Router(object):
	def __init__(self, user, password, ip="192.168.1.1"):
		self.user = user
		self.password = password
		self.rsess = requests.Session()
		self.api_base = 'http://{}/api'.format(ip)
		get_api = self.rsess.get(self.api_base)
		self.api = get_api.json()
	def login(self):
		#get salt first
		pw_to_send = hashlib.sha512(bytes(self.password + self.api['passwordSalt']).encode('utf-8')).hexdigest()
		payload = {"password":pw_to_send}
		clen, strpayload = _content_len_and_str(payload)
		_HEADERS.update({"Content-Length": str(clen)})
		login_res = self.rsess.post(self.api_base + "/login", data=strpayload, headers=_HEADERS)
		return login_res.status_code == 200
	
	def system(self):
		_HEADERS.update({"X-XSRF-TOKEN": self.rsess.cookies.get_dict()["XSRF-TOKEN"]})
		_HEADERS.pop("Origin", None)
		_HEADERS.pop("Content-Length", None)
		res = self.rsess.get(self.api_base + "/settings/system", headers=_HEADERS)
		pprint.pprint(res.json())

	def firmware(self):
		_HEADERS.update({"X-XSRF-TOKEN": self.rsess.cookies.get_dict()["XSRF-TOKEN"]})
		_HEADERS.pop("Origin", None)
		_HEADERS.pop("Content-Length", None)
		res = self.rsess.get(self.api_base + "/firmware", headers=_HEADERS)
		pprint.pprint(res.json())

	def network(self):
		_HEADERS.update({"X-XSRF-TOKEN": self.rsess.cookies.get_dict()["XSRF-TOKEN"]})
		_HEADERS.pop("Origin", None)
		_HEADERS.pop("Content-Length", None)
		res = self.rsess.get(self.api_base + "/network", headers=_HEADERS)
		pprint.pprint(res.json())

	def devices(self):
		_HEADERS.update({"X-XSRF-TOKEN": self.rsess.cookies.get_dict()["XSRF-TOKEN"]})
		_HEADERS.pop("Origin", None)
		_HEADERS.pop("Content-Length", None)
		res = self.rsess.get(self.api_base + "/devices", headers=_HEADERS)
		pprint.pprint(res.json())

	def dnsserver(self):
		_HEADERS.update({"X-XSRF-TOKEN": self.rsess.cookies.get_dict()["XSRF-TOKEN"]})
		_HEADERS.pop("Origin", None)
		_HEADERS.pop("Content-Length", None)
		res = self.rsess.get(self.api_base + "/settings/dnsserver", headers=_HEADERS)
		pprint.pprint(res.json())

	def portforward(self):
		_HEADERS.update({"X-XSRF-TOKEN": self.rsess.cookies.get_dict()["XSRF-TOKEN"]})
		_HEADERS.pop("Origin", None)
		_HEADERS.pop("Content-Length", None)
		res = self.rsess.get(self.api_base + "/firewall/portforward", headers=_HEADERS)
		pprint.pprint(res.json())
		
