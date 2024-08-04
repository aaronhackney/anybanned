import os
from dotenv import load_dotenv
from shun.shun import CiscoSecureShun, CiscoSecureDevices
from graylog.graylog import GraylogQuery

load_dotenv()
GRAYLOG_URL = os.getenv("GRAYLOG_URL")
GRAYLOG_API_KEY = os.getenv("GRAY_APIKEY")
DEVICE_TYPE = CiscoSecureDevices.FTD.value if os.getenv("DEVICE_TYPE") == "FTD" else CiscoSecureDevices.ASA.value
DEVICE_IP = os.getenv("DEVICE_IP")
DEVICE_USER = os.getenv("DEVICE_USER")
DEVICE_PASS = os.getenv("DEVICE_PASS")
SCRIPT_LOG_LEVEL = os.getenv("SCRIPT_LOG_LEVEL")
SSH_SESSION_LOG = os.getenv("SSH_SESSION_LOG")
SCRIPT_LOG = os.getenv("SCRIPT_LOG")


def main():
    # Client to query Graylog
    graylog_client = GraylogQuery(GRAYLOG_URL, GRAYLOG_API_KEY)

    # Client to SSH to firewall for issuiung commands
    shun_client = CiscoSecureShun(
        DEVICE_TYPE,
        DEVICE_IP,
        DEVICE_USER,
        DEVICE_PASS,
        script_log_level=SCRIPT_LOG_LEVEL,
        ssh_session_log=SSH_SESSION_LOG,
        script_log=SCRIPT_LOG,
    )

    # Query Graylog for new shuns to add to firewall
    ips_to_ban = graylog_client.get_ips_to_ban(
        'ftdLogMessage=113015 AND reason:"User was not found"', "66a3a847249c93756c697203", "300", "userIP", size=150
    )

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
