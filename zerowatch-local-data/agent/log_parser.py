import re
from datetime import datetime


AUTH_LOG_PATH = "/var/log/auth.log"


def parse_auth_log():
    failed_login_count = 0
    successful_login_count = 0
    root_login_count = 0
    unique_ips = set()

    try:
        with open(AUTH_LOG_PATH, "r", errors="ignore") as file:
            lines = file.readlines()[-500:]

        for line in lines:
            if "Failed password" in line:
                failed_login_count += 1

                ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    unique_ips.add(ip_match.group(1))

            if "Accepted password" in line or "Accepted publickey" in line:
                successful_login_count += 1

                if " for root " in line:
                    root_login_count += 1

                ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    unique_ips.add(ip_match.group(1))

    except FileNotFoundError:
        print("auth.log file not found. This may depend on your Linux distribution.")

    return {
        "failed_login_count": failed_login_count,
        "successful_login_count": successful_login_count,
        "root_login_count": root_login_count,
        "unique_ip_count": len(unique_ips)
    }


if __name__ == "__main__":
    result = parse_auth_log()
    print(result)
