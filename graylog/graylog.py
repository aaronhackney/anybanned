# Apache License v2.0+ (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import requests
from urllib.parse import quote
from base64 import b64encode
from json import dumps


class GraylogRequests:

    def __init__(self, graylog_api_key) -> None:
        self.creds = self._basic_auth(graylog_api_key, "token")

    def _headers(self):
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": f"Python-AnyBanned",
            "X-Requested-By": "AnyBanned",
            "Authorization": self.creds,
        }

    def post(self, url: str, path: str = None, data: dict = None) -> dict:
        uri = url if path is None else f"{url}{path}"
        print(data)
        result = requests.post(url=uri, json=data, headers=self._headers())
        result.raise_for_status()
        if result.json():
            return result.json()

    def get(self, url: str, path: str = None, query: dict = None) -> dict:
        """Given the API endpoint, path, and query, return the json payload from the API"""
        uri = url if path is None else f"{url}{path}"
        result = requests.get(url=uri, params=query, headers=self._headers())
        result.raise_for_status()
        if result.json():
            return result.json()

    def _basic_auth(self, username, password):
        token = b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        return f"Basic {token}"


class GraylogQuery(GraylogRequests):

    # TODO: Build aggregations using: POST /api/search/aggregate
    # {
    #     "query": "streams:66a3a847249c93756c697203",
    #     "streams": [
    #         "66a3a847249c93756c697203"
    #     ],
    #     "timerange": {
    #         "type": "keyword",
    #         "keyword": "last eight hours"
    #     },
    #     "group_by": [
    #         {
    #             "field": "userIP"
    #         },
    #    {
    #        "field": "userIP_country_code"
    #    }
    #     ],
    #     "metrics": [
    #         {
    #             "function": "count",
    #             "field": "userIP"
    #         }
    #     ]
    # }

    def __init__(self, graylog_url, graylog_api_key) -> None:
        super().__init__(graylog_api_key)
        self.graylog_url = graylog_url

    def extract_ips(self, db_results: dict) -> list:
        """Extract just the ip address from each row of the 'show shun' command"""
        ips_to_ban = [row[0] for row in db_results["datarows"]]
        return ips_to_ban

    # def get_ips_to_ban(self, query: str, stream_id: str, timerange: str, fields: str, size=100):
    def get_ips_to_ban(self, path: str, data: dict, size=100) -> list:
        """Query graylog for logs for the given stream in the given timerange and return 'size' number of logs"""
        results = self.post(self.graylog_url, path=path, data=data)
        ips_to_ban = [ip for ip in results["datarows"] if ip[0] != "(Empty Value)"]
        return ips_to_ban
