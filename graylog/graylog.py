# Apache License v2.0+ (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import requests
from urllib.parse import quote
from base64 import b64encode


class GraylogRequests:

    def __init__(self, graylog_api_key) -> None:
        self.api_client = self.create_session(self._basic_auth(graylog_api_key, "token"))

    def create_session(self, b64_credentials: str) -> str:
        """Helper function to set the auth token and accept headers in the API request"""
        http_session = requests.Session()
        http_session.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": f"Python-AnyBanned",
            "Authorization": b64_credentials,
        }
        return http_session

    def get(self, url: str, path: str = None, query: dict = None):
        """Given the API endpoint, path, and query, return the json payload from the API"""
        uri = url if path is None else f"{url}/{path}"
        result = self.api_client.get(
            url=uri,
            params=query,
        )
        result.raise_for_status()
        if result.json():
            return result.json()

    def _basic_auth(self, username, password):
        token = b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        return f"Basic {token}"


class GraylogQuery(GraylogRequests):

    def __init__(self, graylog_url, graylog_api_key) -> None:
        super().__init__(graylog_api_key)
        self.graylog_url = graylog_url

    def extract_ips(self, db_results: dict) -> list:
        """Extract just the ip address from each row of the 'show shun' command"""
        # ips_to_ban = set()
        ips_to_ban = [row[0] for row in db_results["datarows"]]
        # for row in db_results["datarows"]:
        #     ips_to_ban.add(row[0])
        return ips_to_ban

    def get_ips_to_ban(self, query: str, stream_id: str, timerange: str, fields: str, size=100):
        """Query graylog for logs for the given stream in the given timerange and return 'size' number of logs"""
        q = {"query": query, "streams": stream_id, "timerange": timerange, "fields": fields, "size": size}
        results = self.get(self.graylog_url, "/api/search/messages", query=q)
        ips_to_ban = [ip[0] for ip in results["datarows"]]
        return set(ips_to_ban)
