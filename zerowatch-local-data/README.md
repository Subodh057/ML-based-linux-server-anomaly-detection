# ZeroWatch Local Data: ML-Based Linux Server Anomaly Detection

ZeroWatch Local Data is a machine learning-based Linux server anomaly detection project. It collects real-time local server telemetry and uses an Isolation Forest model to learn normal system behavior and detect suspicious deviations.

## Features

- Collects real-time Linux server telemetry
- Monitors CPU usage, memory usage, disk usage, process count, network connections, and SSH login-related activity
- Saves collected telemetry into CSV format
- Trains an Isolation Forest anomaly detection model
- Detects normal and anomalous server behavior
- Provides dashboard visualization for server activity and anomaly results

## Tech Stack

- Python
- Linux
- psutil
- Pandas
- Scikit-learn
- Isolation Forest
- Streamlit
- Joblib

## Project Structure

```txt
zerowatch-local-data/
├── agent/
│   ├── collector.py
│   └── log_parser.py
├── backend/
│   ├── model.py
│   └── test_model.py
├── dashboard/
│   └── app.py
├── data/
├── ml/
│   └── train_model.py
├── requirements.txt
└── README.md