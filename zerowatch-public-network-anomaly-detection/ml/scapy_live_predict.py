import os
import time
import joblib
import pandas as pd

from scapy.all import sniff, IP, TCP, UDP


MODEL_PATH = "models/random_forest_model.pkl"
FEATURE_COLUMNS_PATH = "models/feature_columns.pkl"


def capture_packets(duration=5):
    packets = []

    def packet_callback(packet):
        if IP in packet:
            packets.append(packet)

    print(f"Capturing live packets for {duration} seconds...")
    sniff(iface="lo",prn=packet_callback, store=False, timeout=duration)

    return packets


def extract_live_features(packets, duration=5):
    total_fwd_packets = 0
    total_bwd_packets = 0

    total_fwd_bytes = 0
    total_bwd_bytes = 0

    packet_lengths = []

    syn_count = 0
    ack_count = 0
    fin_count = 0
    rst_count = 0
    psh_count = 0
    urg_count = 0

    for packet in packets:
        packet_size = len(packet)
        packet_lengths.append(packet_size)

        # Simple approximation:
        # outgoing/incoming direction is not perfectly known here,
        # so we divide packets based on source/destination comparison.
        if IP in packet:
            total_fwd_packets += 1
            total_fwd_bytes += packet_size

        if TCP in packet:
            flags = packet[TCP].flags

            if flags & 0x02:
                syn_count += 1
            if flags & 0x10:
                ack_count += 1
            if flags & 0x01:
                fin_count += 1
            if flags & 0x04:
                rst_count += 1
            if flags & 0x08:
                psh_count += 1
            if flags & 0x20:
                urg_count += 1

        if UDP in packet:
            pass

    total_packets = max(len(packets), 1)
    total_bytes = total_fwd_bytes + total_bwd_bytes

    flow_duration = duration * 1_000_000  # microseconds, similar style to CIC features

    min_packet_length = min(packet_lengths) if packet_lengths else 0
    max_packet_length = max(packet_lengths) if packet_lengths else 0
    avg_packet_size = sum(packet_lengths) / total_packets if packet_lengths else 0

    flow_bytes_per_sec = total_bytes / duration if duration > 0 else 0
    flow_packets_per_sec = total_packets / duration if duration > 0 else 0

    fwd_packet_length_mean = total_fwd_bytes / max(total_fwd_packets, 1)
    bwd_packet_length_mean = total_bwd_bytes / max(total_bwd_packets, 1)

    features = {
        "Destination Port": 0,
        "Flow Duration": flow_duration,

        "Total Fwd Packets": total_fwd_packets,
        "Total Backward Packets": total_bwd_packets,

        "Total Length of Fwd Packets": total_fwd_bytes,
        "Total Length of Bwd Packets": total_bwd_bytes,

        "Fwd Packet Length Max": max_packet_length,
        "Fwd Packet Length Min": min_packet_length,
        "Fwd Packet Length Mean": fwd_packet_length_mean,
        "Fwd Packet Length Std": 0,

        "Bwd Packet Length Max": 0,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": bwd_packet_length_mean,
        "Bwd Packet Length Std": 0,

        "Flow Bytes/s": flow_bytes_per_sec,
        "Flow Packets/s": flow_packets_per_sec,

        "Flow IAT Mean": 0,
        "Flow IAT Std": 0,
        "Flow IAT Max": 0,
        "Flow IAT Min": 0,

        "Fwd IAT Total": 0,
        "Fwd IAT Mean": 0,
        "Fwd IAT Std": 0,
        "Fwd IAT Max": 0,
        "Fwd IAT Min": 0,

        "Bwd IAT Total": 0,
        "Bwd IAT Mean": 0,
        "Bwd IAT Std": 0,
        "Bwd IAT Max": 0,
        "Bwd IAT Min": 0,

        "Fwd PSH Flags": psh_count,
        "Bwd PSH Flags": 0,
        "Fwd URG Flags": urg_count,
        "Bwd URG Flags": 0,

        "Fwd Header Length": 0,
        "Bwd Header Length": 0,

        "Fwd Packets/s": total_fwd_packets / duration if duration > 0 else 0,
        "Bwd Packets/s": total_bwd_packets / duration if duration > 0 else 0,

        "Min Packet Length": min_packet_length,
        "Max Packet Length": max_packet_length,
        "Packet Length Mean": avg_packet_size,
        "Packet Length Std": 0,
        "Packet Length Variance": 0,

        "FIN Flag Count": fin_count,
        "SYN Flag Count": syn_count,
        "RST Flag Count": rst_count,
        "PSH Flag Count": psh_count,
        "ACK Flag Count": ack_count,
        "URG Flag Count": urg_count,
        "CWE Flag Count": 0,
        "ECE Flag Count": 0,

        "Down/Up Ratio": 0,
        "Average Packet Size": avg_packet_size,
        "Avg Fwd Segment Size": fwd_packet_length_mean,
        "Avg Bwd Segment Size": bwd_packet_length_mean,

        "Fwd Header Length.1": 0,

        "Fwd Avg Bytes/Bulk": 0,
        "Fwd Avg Packets/Bulk": 0,
        "Fwd Avg Bulk Rate": 0,

        "Bwd Avg Bytes/Bulk": 0,
        "Bwd Avg Packets/Bulk": 0,
        "Bwd Avg Bulk Rate": 0,

        "Subflow Fwd Packets": total_fwd_packets,
        "Subflow Fwd Bytes": total_fwd_bytes,
        "Subflow Bwd Packets": total_bwd_packets,
        "Subflow Bwd Bytes": total_bwd_bytes,

        "Init_Win_bytes_forward": 0,
        "Init_Win_bytes_backward": 0,

        "act_data_pkt_fwd": total_fwd_packets,
        "min_seg_size_forward": 0,

        "Active Mean": 0,
        "Active Std": 0,
        "Active Max": 0,
        "Active Min": 0,

        "Idle Mean": 0,
        "Idle Std": 0,
        "Idle Max": 0,
        "Idle Min": 0,
    }

    return features


def build_model_input(features, feature_columns):
    model_input = {}

    for col in feature_columns:
        model_input[col] = features.get(col, 0)

    return pd.DataFrame([model_input])


def live_predict():
    if not os.path.exists(MODEL_PATH):
        print("Model not found. Run: python ml/train_model.py")
        return

    if not os.path.exists(FEATURE_COLUMNS_PATH):
        print("Feature columns not found. Run: python ml/train_model.py")
        return

    model = joblib.load(MODEL_PATH)
    feature_columns = joblib.load(FEATURE_COLUMNS_PATH)

    print("ZeroWatch Live Network Prediction Started")
    print("Press CTRL + C to stop.\n")

    while True:
        duration = 30

        packets = capture_packets(duration=duration)
        features = extract_live_features(packets, duration=duration)
        X_live = build_model_input(features, feature_columns)

        prediction = model.predict(X_live)[0]

        predicted_label = "BENIGN" if prediction == 0 else "ATTACK"

        print("Live Network Analysis")
        print("---------------------")
        print("Packets Captured:", len(packets))
        print("Flow Bytes/s:", round(features["Flow Bytes/s"], 2))
        print("Flow Packets/s:", round(features["Flow Packets/s"], 2))
        print("SYN Flags:", features["SYN Flag Count"])
        print("ACK Flags:", features["ACK Flag Count"])
        print("Prediction:", predicted_label)

        if predicted_label == "ATTACK":
            print("Alert: Suspicious live network behavior detected.")
        else:
            print("Status: Live network behavior appears normal.")

        print()


if __name__ == "__main__":
    live_predict()
