import os
import joblib
import pandas as pd


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


def detect_anomaly(data):
    if not os.path.exists(MODEL_PATH):
        return {"error": "Model not found. Train the model first."}

    if not os.path.exists(SCALER_PATH):
        return {"error": "Scaler not found. Train the model first."}

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    df = pd.DataFrame([data])
    df = df[FEATURES]

    scaled_data = scaler.transform(df)

    prediction = model.predict(scaled_data)[0]
    score = model.decision_function(scaled_data)[0]

    if prediction == -1:
        status = "anomaly"
        risk = "high"
    else:
        status = "normal"
        risk = "low"

    return {
        "status": status,
        "risk": risk,
        "anomaly_score": float(score),
        "prediction": int(prediction)
    }
