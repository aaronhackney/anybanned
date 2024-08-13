import os
import requests
import helpers
from dotenv import load_dotenv
from shun.shun import CiscoSecureShun, CiscoSecureDevices
from graylog.graylog import GraylogQuery

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

if os.getenv("GRAYLOG_ENABLE"):
    GRAYLOG_URL = os.getenv("GRAYLOG_URL")
    GRAYLOG_API_KEY = os.getenv("GRAY_APIKEY")

if os.getenv("IP_WEB_FEED_ENABLED"):
    IP_WEB_FEED_URL = os.getenv("IP_WEB_FEED_URL")


def get_graylog_ips_to_ban(url: str, token: str) -> list:
    """Query the Graylog syslog server for the IP addresses we need to ban"""
    graylog_client = GraylogQuery(url, token)
    return graylog_client.get_ips_to_ban(
        'ftdLogMessage=113015 AND reason:"User was not found"', "66a3a847249c93756c697203", "300", "userIP", size=150
    )


def get_web_feed_ips_to_ban(web_feed: str) -> list:
    results = requests.get(web_feed)
    results.raise_for_status()
    return [line for line in results.text.splitlines() if helpers.is_ip_address(line)]


def main():
    graylog_ips_to_ban = list()
    web_feed_ips_to_ban = list()

    if GRAYLOG_URL and GRAYLOG_API_KEY:
        graylog_ips_to_ban = get_graylog_ips_to_ban(GRAYLOG_URL, GRAYLOG_API_KEY)

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

    for ips_to_ban in [graylog_ips_to_ban, web_feed_ips_to_ban]:

        # Query firewall for shuns that already exist
        shunned = shun_client.extract_shunned_ips(shun_client.run_cmd(["show shun"]))
        shun_client.logger.debug(f"{len(shunned)} existing shuns found on firewall")

        # Remove the existing IPs from the ips_to_ban and shun the remaining IPs on the firewall
        shuns_issued = shun_client.run_cmd(shun_client.calculate_new_shuns(ips_to_ban, shunned))

        for cli_shun in shuns_issued:
            shun_client.logger.debug(cli_shun)

        for ip in ips_to_ban:
            print(f"shun {ip}")


if __name__ == "__main__":
    main()
