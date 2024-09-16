# Apache License v2.0+ (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import requests
from base64 import b64encode


class GraylogRequests:

    def __init__(self, graylog_api_key) -> None:
        self.creds = self._basic_auth(graylog_api_key, "token")

    def _headers(self):
        """Build the required headers that Graylog expects"""
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": f"Python-AnyBanned",
            "X-Requested-By": "AnyBanned",
            "Authorization": self.creds,
        }

    def post(self, url: str, path: str = None, data: dict = None) -> dict:
        """Post operation to Graylog"""
        uri = url if path is None else f"{url}{path}"
        result = requests.post(url=uri, json=data, headers=self._headers())
        result.raise_for_status()
        if result.json():
            return result.json()

    def get(self, url: str, path: str = None, query: dict = None) -> dict:
        """GET operation to Graylog"""
        uri = url if path is None else f"{url}{path}"
        result = requests.get(url=uri, params=query, headers=self._headers())
        result.raise_for_status()
        if result.json():
            return result.json()

    def _basic_auth(self, username, password):
        """Give a Graylog API key, return the base 64 creds"""
        token = b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        return f"Basic {token}"


class GraylogQuery(GraylogRequests):

    def __init__(self, graylog_url, graylog_api_key) -> None:
        super().__init__(graylog_api_key)
        self.graylog_url = graylog_url

    def get_recent_login_failures(self, query: str, stream_id: str, timerange: str, fields: str = "userIP", size=150):
        """Query graylog for the login failures for the last x number of seconds"""
        q = {"query": query, "streams": stream_id, "timerange": timerange, "fields": fields, "size": size}
        results = self.get(self.graylog_url, "/api/search/messages", query=q)
        return [ip[0] for ip in results["datarows"]]

    def get_ip_history(self, search_ip: str, stream_id: str) -> list:
        """Query graylog for this IP addresses history for the given stream in the given timerange"""
        search = {
            "query": f'streams:{stream_id} AND userIP: "{search_ip}"',
            "streams": [stream_id],
            "timerange": {"type": "keyword", "keyword": "last twentyfour hours"},
            "group_by": [{"field": "userIP"}, {"field": "userIP_country_code"}],
            "metrics": [{"function": "count", "field": "userIP"}],
        }
        results = self.post(self.graylog_url, path="/api/search/aggregate", data=search)
        return {
            "ip": results["datarows"][0][0],
            "country": results["datarows"][0][1],
            "fail_count": results["datarows"][0][2],
        }
