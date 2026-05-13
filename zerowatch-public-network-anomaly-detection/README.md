# ZeroWatch Public Network Anomaly Detection

ZeroWatch Public Network Anomaly Detection is an ML-based network intrusion detection project using the CIC-IDS2017 public cybersecurity dataset. It trains a Random Forest classifier to classify network traffic as BENIGN or ATTACK and includes Scapy-based live network traffic analysis.

## Features

- Uses CIC-IDS2017 public network traffic dataset
- Preprocesses network flow data
- Converts labels into BENIGN and ATTACK classes
- Trains a Random Forest classifier
- Evaluates model using accuracy, confusion matrix, and classification report
- Shows feature importance
- Provides Streamlit dashboard visualization
- Includes Scapy-based live packet capture and traffic analysis

## Tech Stack

- Python
- CIC-IDS2017
- Pandas
- Scikit-learn
- Random Forest
- Streamlit
- Scapy
- Joblib

## Project Structure

```txt
zerowatch-public-network-anomaly-detection/
├── data/
│   ├── raw/
│   └── processed/
├── dashboard/
│   └── app.py
├── ml/
│   ├── train_model.py
│   ├── predict.py
│   ├── scapy_capture_test.py
│   └── scapy_live_predict.py
├── models/
├── reports/
├── requirements.txt
└── README.md