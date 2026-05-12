import os
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


DATA_PATH = "data/live_data.csv"
MODEL_PATH = "ml/anomaly_model.pkl"
SCALER_PATH = "ml/scaler.pkl"


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


def train_model():
    print("Starting model training...")

    if not os.path.exists(DATA_PATH):
        print("live_data.csv not found. Run collector.py first.")
        return

    df = pd.read_csv(DATA_PATH)
    df = df.dropna()

    print(f"Rows found: {len(df)}")

    if len(df) < 20:
        print("Not enough data. Collect at least 20 rows first.")
        return

    X = df[FEATURES]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )

    model.fit(X_scaled)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    print("Model trained successfully.")
    print(f"Model saved to: {MODEL_PATH}")
    print(f"Scaler saved to: {SCALER_PATH}")


if __name__ == "__main__":
    train_model()
