import pandas as pd
from model import detect_anomaly


DATA_PATH = "data/live_data.csv"

FEATURES = [
    "cpu_usage",
    "memory_usage",
    "disk_usage",
    "running_process_count",
    "network_connections",
    "bytes_sent",
    "bytes_recv",
    "failed_login_count",
    "successful_login_count",
    "root_login_count",
    "unique_ip_count"
]


df = pd.read_csv(DATA_PATH)

# Take last real server data row
last_row = df.iloc[-1][FEATURES].to_dict()

suspicious_sample = {
    "cpu_usage": 98.0,
    "memory_usage": 95.0,
    "disk_usage": 90.0,
    "running_process_count": 600,
    "network_connections": 300,
    "bytes_sent": 900000000,
    "bytes_recv": 800000000,
    "failed_login_count": 50,
    "successful_login_count": 2,
    "root_login_count": 1,
    "unique_ip_count": 20
}

print("Real latest server sample:")
print(last_row)
print(detect_anomaly(last_row))

print("\nSuspicious sample:")
print(suspicious_sample)
print(detect_anomaly(suspicious_sample))
