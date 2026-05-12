import psutil
import socket
import json
import time
import sys
import os
import csv
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from log_parser import parse_auth_log


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_FILE = os.path.join(BASE_DIR, "data", "live_data.csv")


def collect_system_data():
    auth_data = parse_auth_log()

    data = {
        "timestamp": datetime.now().isoformat(),
        "hostname": socket.gethostname(),

        "cpu_usage": psutil.cpu_percent(interval=1),
        "memory_usage": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage("/").percent,

        "running_process_count": len(psutil.pids()),
        "network_connections": len(psutil.net_connections(kind="inet")),

        "bytes_sent": psutil.net_io_counters().bytes_sent,
        "bytes_recv": psutil.net_io_counters().bytes_recv,

        "failed_login_count": auth_data["failed_login_count"],
        "successful_login_count": auth_data["successful_login_count"],
        "root_login_count": auth_data["root_login_count"],
        "unique_ip_count": auth_data["unique_ip_count"]
    }

    return data


def save_to_csv(data):
    os.makedirs(os.path.dirname(CSV_FILE), exist_ok=True)

    file_exists = os.path.isfile(CSV_FILE)

    with open(CSV_FILE, "a", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=data.keys())

        if not file_exists:
            writer.writeheader()

        writer.writerow(data)


if __name__ == "__main__":
    print(f"Saving data to: {CSV_FILE}")

    while True:
        server_data = collect_system_data()
        save_to_csv(server_data)

        print(json.dumps(server_data, indent=4))
        time.sleep(5)
