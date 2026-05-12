import os
import joblib
import pandas as pd


MODEL_PATH = "models/random_forest_model.pkl"
FEATURE_COLUMNS_PATH = "models/feature_columns.pkl"
DATA_PATH = "data/raw/cicids2017.csv"


def clean_column_names(df):
    df.columns = df.columns.str.strip()
    return df


def predict_sample():
    if not os.path.exists(MODEL_PATH):
        print("Model not found. Run: python ml/train_model.py")
        return

    if not os.path.exists(FEATURE_COLUMNS_PATH):
        print("Feature columns file not found. Run: python ml/train_model.py")
        return

    if not os.path.exists(DATA_PATH):
        print("Dataset not found. Put cicids2017.csv inside data/raw/")
        return

    model = joblib.load(MODEL_PATH)
    feature_columns = joblib.load(FEATURE_COLUMNS_PATH)

    df = pd.read_csv(DATA_PATH)
    df = clean_column_names(df)

    df = df.replace([float("inf"), float("-inf")], pd.NA)
    df = df.dropna()

    sample = df.sample(1, random_state=10)

    actual_label = sample["Label"].values[0]

    X = sample[feature_columns]

    prediction = model.predict(X)[0]

    predicted_label = "BENIGN" if prediction == 0 else "ATTACK"

    print("Actual Label:", actual_label)
    print("Predicted Label:", predicted_label)


if __name__ == "__main__":
    predict_sample()
