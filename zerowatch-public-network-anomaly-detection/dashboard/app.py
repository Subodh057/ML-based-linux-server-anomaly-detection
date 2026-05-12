import os
import pandas as pd
import joblib
import streamlit as st

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report


DATA_PATH = "data/raw/cicids2017.csv"
MODEL_PATH = "models/random_forest_model.pkl"
FEATURE_COLUMNS_PATH = "models/feature_columns.pkl"


st.set_page_config(
    page_title="ZeroWatch Public Network Anomaly Detection",
    layout="wide"
)

st.title("ZeroWatch: Public Network Anomaly Detection")
st.caption("ML-based network intrusion detection using CIC-IDS2017 public dataset and live traffic analysis support.")


def clean_column_names(df):
    df.columns = df.columns.str.strip()
    return df


if not os.path.exists(DATA_PATH):
    st.error("Dataset not found. Place cicids2017.csv inside data/raw/")
    st.stop()

if not os.path.exists(MODEL_PATH):
    st.error("Model not found. Run: python ml/train_model.py")
    st.stop()

if not os.path.exists(FEATURE_COLUMNS_PATH):
    st.error("Feature columns file not found. Run: python ml/train_model.py")
    st.stop()


@st.cache_data
def load_data():
    df = pd.read_csv(DATA_PATH)
    df = clean_column_names(df)
    df = df.replace([float("inf"), float("-inf")], pd.NA)
    df = df.dropna()

    df["target"] = df["Label"].apply(
        lambda x: 0 if str(x).strip().upper() == "BENIGN" else 1
    )

    return df


@st.cache_resource
def load_model():
    model = joblib.load(MODEL_PATH)
    feature_columns = joblib.load(FEATURE_COLUMNS_PATH)
    return model, feature_columns


df = load_data()
model, feature_columns = load_model()

X = df[feature_columns]
y = df["target"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

total_records = len(df)
benign_count = len(df[df["target"] == 0])
attack_count = len(df[df["target"] == 1])

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Records", f"{total_records:,}")
col2.metric("Benign Records", f"{benign_count:,}")
col3.metric("Attack Records", f"{attack_count:,}")
col4.metric("Model Accuracy", f"{accuracy * 100:.2f}%")

st.divider()

col5, col6 = st.columns(2)

with col5:
    st.subheader("Traffic Label Distribution")
    label_counts = df["Label"].value_counts()
    st.bar_chart(label_counts)

with col6:
    st.subheader("Binary Class Distribution")
    binary_counts = df["target"].map({0: "BENIGN", 1: "ATTACK"}).value_counts()
    st.bar_chart(binary_counts)

st.divider()

col7, col8 = st.columns(2)

with col7:
    st.subheader("Confusion Matrix")
    cm = confusion_matrix(y_test, y_pred)
    cm_df = pd.DataFrame(
        cm,
        index=["Actual BENIGN", "Actual ATTACK"],
        columns=["Predicted BENIGN", "Predicted ATTACK"]
    )
    st.dataframe(cm_df, use_container_width=True)

with col8:
    st.subheader("Classification Report")
    report = classification_report(
        y_test,
        y_pred,
        target_names=["BENIGN", "ATTACK"],
        output_dict=True
    )
    report_df = pd.DataFrame(report).transpose()
    st.dataframe(report_df, use_container_width=True)

st.divider()

st.subheader("Feature Importance")

importance_df = pd.DataFrame({
    "Feature": feature_columns,
    "Importance": model.feature_importances_
}).sort_values(by="Importance", ascending=False)

st.dataframe(importance_df.head(20), use_container_width=True)
st.bar_chart(importance_df.head(15).set_index("Feature"))

st.divider()

st.subheader("Manual Sample Prediction")

sample_index = st.number_input(
    "Enter dataset row index",
    min_value=0,
    max_value=len(df) - 1,
    value=0,
    step=1
)

sample = df.iloc[[sample_index]]
actual_label = sample["Label"].values[0]
prediction = model.predict(sample[feature_columns])[0]
predicted_label = "BENIGN" if prediction == 0 else "ATTACK"

col9, col10 = st.columns(2)

with col9:
    st.write("Actual Label:")
    st.info(actual_label)

with col10:
    st.write("Predicted Label:")
    if predicted_label == "ATTACK":
        st.error(predicted_label)
    else:
        st.success(predicted_label)

st.subheader("Selected Network Flow")
st.dataframe(sample[["Label"] + feature_columns[:10]], use_container_width=True)

st.divider()

st.subheader("Dataset Preview")
st.dataframe(df.head(20), use_container_width=True)

st.info(
    "Note: Live Scapy-based prediction is handled by ml/scapy_live_predict.py. "
    "This dashboard currently visualizes the public dataset model, evaluation metrics, "
    "feature importance, and manual prediction."
)
