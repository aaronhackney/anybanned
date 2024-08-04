# Apache License v2.0+ (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
from enum import Enum
from netmiko import ConnectHandler


class CiscoSecureDevices(Enum):
    ASA = "cisco_asa_ssh"
    FTD = "cisco_ftd_ssh"


class CiscoSecureShun:
    def __init__(
        self,
        device_type: CiscoSecureDevices,
        device_ip: str,
        device_user: str,
        device_pass: str,
        ssh_session_log: str = "ssh_session.log",
        script_log: str = "shun.log",
        script_log_level: str = "WARNING",
    ) -> None:
        self.device_type = device_type
        self.device_ip = device_ip
        self.device_user = device_user
        self.device_pass = device_pass
        self.ssh_session_log = ssh_session_log
        self.device = {
            "device_type": device_type,
            "host": device_ip,
            "username": device_user,
            "password": device_pass,
            "session_log": ssh_session_log,
        }
        self.logger = self.logging_init(script_log_level, script_log)

    def logging_init(self, script_log_level: str, script_log_file: str):
        """Set up script logging"""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.getLevelName(script_log_level))
        fh = logging.FileHandler(script_log_file)
        fh.setLevel(logging.getLevelName(script_log_level))
        fh.setFormatter(logging.Formatter(fmt="%(asctime)s: %(levelname)s: %(message)s"))
        logger.addHandler(fh)
        return logger

    def run_cmd(self, command_set: list) -> list:
        """Run CLI command(s) and return the cli output"""
        return_output = list()
        with ConnectHandler(**self.device) as net_connect:
            for command in command_set:
                output = net_connect.send_command(command)
                return_output.append(output.splitlines())
        return return_output

    def extract_shunned_ips(self, cli_output: list) -> list:
        """Given a list of shun statements, return"""
        shunned = [[line.split(" ")[2] for line in row] for row in cli_output]
        return shunned[0] if len(shunned) else None

    def calculate_new_shuns(self, syslog_ips: list, shunned_ips: list) -> list:
        """Compare the existing FW shun list to the proposed shun additions and only return the needed shun IPs"""
        new_shuns = list(set(syslog_ips) - set(shunned_ips))
        self.logger.debug(f"New shuns to issue: {len(new_shuns)}")
        return ["shun " + ip for ip in new_shuns]
