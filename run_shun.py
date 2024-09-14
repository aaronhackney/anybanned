import os
import requests
import helpers
from dotenv import load_dotenv
from shun.shun import CiscoSecureShun, CiscoSecureDevices
from graylog.graylog import GraylogQuery
from json import loads

# Load the needed environment variables from a .env file
load_dotenv()

# Set up the constants from the environment variables for easier readability
DEVICE_TYPE = (
    CiscoSecureDevices.FTD.value if os.getenv("DEVICE_TYPE").upper() == "FTD" else CiscoSecureDevices.ASA.value
)
DEVICE_IP = os.getenv("DEVICE_IP")
DEVICE_USER = os.getenv("DEVICE_USER")
DEVICE_PASS = os.getenv("DEVICE_PASS")
SCRIPT_LOG_LEVEL = os.getenv("SCRIPT_LOG_LEVEL").upper()
SSH_SESSION_LOG = os.getenv("SSH_SESSION_LOG")
SCRIPT_LOG = os.getenv("SCRIPT_LOG")
GRAYLOG_STREAM_ID = os.getenv("GRAYLOG_STREAM_ID")
TIME_INTERVAL = os.getenv("TIME_INTERVAL")
BAN_SETTINGS = loads(os.getenv("BAN_SETTINGS"))

if os.getenv("GRAYLOG_ENABLE"):
    GRAYLOG_URL = os.getenv("GRAYLOG_URL")
    GRAYLOG_API_KEY = os.getenv("GRAY_APIKEY")

if os.getenv("IP_WEB_FEED_ENABLED"):
    IP_WEB_FEED_URL = os.getenv("IP_WEB_FEED_URL")


def get_graylog_ips_to_ban(url: str, token: str, stream_id: str, time_interval: str) -> list:
    """Query the Graylog syslog server for the IP addresses we need to ban"""
    graylog_client = GraylogQuery(url, token)
    search = {
        "query": f"streams:{stream_id}",
        "streams": [stream_id],
        "timerange": {"type": "keyword", "keyword": time_interval},
        "group_by": [{"field": "userIP"}, {"field": "userIP_country_code"}],
        "metrics": [{"function": "count", "field": "userIP"}],
    }
    return graylog_client.get_ips_to_ban("/api/search/aggregate", search)


def get_web_feed_ips_to_ban(web_feed: str) -> list:
    results = requests.get(web_feed)
    results.raise_for_status()
    return [line for line in results.text.splitlines() if helpers.is_ip_address(line)]


def is_should_shun(ip: list, ban_settings) -> bool:
    """Check to see if the number of login failures from the IP address meets our threashold for banishment"""
    for key, value in ban_settings.items():
        if ip[1].lower() == key.lower():
            if ip[2] == 1:
                pass
            if ip[2] >= value:
                return True
    return False


def main():
    filtered_ips_to_ban = list()
    graylog_ips_to_ban = list()
    web_feed_ips_to_ban = list()

    if GRAYLOG_URL and GRAYLOG_API_KEY:
        graylog_ips_to_ban = get_graylog_ips_to_ban(GRAYLOG_URL, GRAYLOG_API_KEY, GRAYLOG_STREAM_ID, TIME_INTERVAL)
        # New parameters: How many attempts before we ban? Country to ban by default?
        for ip in graylog_ips_to_ban:
            if is_should_shun(ip, BAN_SETTINGS):
                filtered_ips_to_ban.append(ip)
    del graylog_ips_to_ban

    if IP_WEB_FEED_URL:
        web_feed_ips_to_ban = get_web_feed_ips_to_ban(IP_WEB_FEED_URL)

    # Client to SSH to firewall for issuiung shun commands
    shun_client = CiscoSecureShun(
        DEVICE_TYPE,
        DEVICE_IP,
        DEVICE_USER,
        DEVICE_PASS,
        script_log_level=SCRIPT_LOG_LEVEL,
        ssh_session_log=SSH_SESSION_LOG,
        script_log=SCRIPT_LOG,
    )

    graylog_ips_to_ban = [item[0] for item in filtered_ips_to_ban]
    # TODO: log the ip, geoip, and number of failures
    for ips_to_ban in [graylog_ips_to_ban]:

        # Query firewall for shuns that already exist
        shunned = shun_client.extract_shunned_ips(shun_client.run_cmd(["show shun"]))
        shun_client.logger.debug(f"{len(shunned)} existing shuns found on firewall")

        # Remove the existing IPs from the ips_to_ban and shun the remaining IPs on the firewall
        shuns_issued = shun_client.run_cmd(shun_client.calculate_new_shuns(ips_to_ban, shunned))

        for cli_shun in shuns_issued:
            shun_client.logger.debug(cli_shun)


if __name__ == "__main__":
    main()
