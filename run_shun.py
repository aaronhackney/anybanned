# Apache License v2.0+ (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import requests
import ipaddress
from json import loads
from dotenv import dotenv_values
from graylog.graylog import GraylogQuery
from shun.shun import CiscoSecureShun, CiscoSecureDevices

# Load the needed variables from a .env file
config = dotenv_values(".env")
DEVICE_TYPE = CiscoSecureDevices[config.get("DEVICE_TYPE")].value
DEVICE_IP = config.get("DEVICE_IP")
DEVICE_USER = config.get("DEVICE_USER")
DEVICE_PASS = config.get("DEVICE_PASS")
SCRIPT_LOG_LEVEL = config.get("SCRIPT_LOG_LEVEL").upper()
SSH_SESSION_LOG = config.get("SSH_SESSION_LOG")
SCRIPT_LOG = config.get("SCRIPT_LOG")
PAGE_SIZE = 150

# Optional Graylog integration
GRAYLOG_URL = config.get("GRAYLOG_URL")
GRAYLOG_API_KEY = config.get("GRAY_APIKEY")
GRAYLOG_STREAM_ID = config.get("GRAYLOG_STREAM_ID")
GRAYLOG_FAIL_QUERY = config.get("GRAYLOG_FAIL_QUERY")
GRAYLOG_TIME_RANGE = config.get("GRAYLOG_TIME_RANGE")
GRAYLOG_BAN_SETTINGS = loads(config.get("GRAYLOG_BAN_SETTINGS")) if config.get("GRAYLOG_BAN_SETTINGS") else None

# Optional web feed integration
IP_WEB_FEED_URL = config.get("IP_WEB_FEED_URL")


def get_shun_list(candidate_ips: list, ban_settings: dict) -> list:
    """Given a list of IP history from the logging server, determine if it meets the criteria for shunning"""
    shun_me = list()
    for candidate_ip in candidate_ips:
        if candidate_ip["country"] in ban_settings:
            if candidate_ip["fail_count"] >= ban_settings[candidate_ip["country"]]:
                shun_me.append(candidate_ip["ip"])
                print(f"Shun candidate: {candidate_ip}")
        elif candidate_ip["fail_count"] >= ban_settings["default"]:
            shun_me.append(candidate_ip["ip"])
            print(f"Shun candidate: {candidate_ip}")
        else:
            print(f"{candidate_ip} did not meet the threshold for shunning yet...")
    return shun_me


def is_ip(address: str) -> bool:
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def get_web_feed_ips_to_ban(web_feed: str) -> list:
    results = requests.get(web_feed)
    results.raise_for_status()
    return [line for line in results.text.splitlines() if is_ip(line)]


def main():
    graylog_recent_failures = list()
    graylog_ip_history = list()
    candidate_shun_list = list()

    if GRAYLOG_URL and GRAYLOG_API_KEY:
        graylog_client = GraylogQuery(GRAYLOG_URL, GRAYLOG_API_KEY)

        # Get the login failures for the last GRAYLOG_TIME_RANGE seconds
        graylog_recent_failures = graylog_client.get_recent_login_failures(
            GRAYLOG_FAIL_QUERY, GRAYLOG_STREAM_ID, GRAYLOG_TIME_RANGE
        )

        # for each IP in the list, get the aggregation....
        for ip in set(graylog_recent_failures):
            graylog_ip_history.append(graylog_client.get_ip_history(ip, GRAYLOG_STREAM_ID))

        # Make the decison to shun or not to shun based on .env settings
        candidate_shun_list = candidate_shun_list + get_shun_list(graylog_ip_history, GRAYLOG_BAN_SETTINGS)

    if IP_WEB_FEED_URL:
        candidate_shun_list = candidate_shun_list + get_web_feed_ips_to_ban(IP_WEB_FEED_URL)

    # If we have candidates to shun, issue the shuns to the firewall if they do not already exist
    if candidate_shun_list:

        # Client to SSH to firewall for issuiung show shun and shun commands
        shun_client = CiscoSecureShun(
            DEVICE_TYPE,
            DEVICE_IP,
            DEVICE_USER,
            DEVICE_PASS,
            script_log_level=SCRIPT_LOG_LEVEL,
            ssh_session_log=SSH_SESSION_LOG,
            script_log=SCRIPT_LOG,
        )

        # Get list of IPs already shunned on the firewall
        shunned = shun_client.extract_shunned_ips(shun_client.run_cmd(["show shun"]))
        shun_client.logger.debug(f"{len(shunned)} existing shuns found on firewall")

        # Get the final list of IP Addresses to shun and make it so
        for ip in list(set(candidate_shun_list) - set(shunned)):
            shuns_issued = shun_client.run_cmd(f"shun {ip}")
            for cli_shun in shuns_issued:
                shun_client.logger.debug(cli_shun)


if __name__ == "__main__":
    main()
