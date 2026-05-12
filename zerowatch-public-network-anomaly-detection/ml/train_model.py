import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix


DATA_PATH = "data/raw/cicids2017.csv"
MODEL_PATH = "models/random_forest_model.pkl"


def clean_column_names(df):
    df.columns = df.columns.str.strip()
    return df


def train_model():
    if not os.path.exists(DATA_PATH):
        print(f"Dataset not found: {DATA_PATH}")
        return

    print("Loading dataset...")
    df = pd.read_csv(DATA_PATH)
    df = clean_column_names(df)

    print("Dataset loaded successfully.")
    print(f"Rows: {df.shape[0]}")
    print(f"Columns: {df.shape[1]}")

    if "Label" not in df.columns:
        print("Label column not found.")
        print("Available columns:")
        print(df.columns.tolist())
        return

    df = df.replace([float("inf"), float("-inf")], pd.NA)
    df = df.dropna()

    print("Labels found:")
    print(df["Label"].value_counts())

    # Convert labels to binary: BENIGN = 0, Attack = 1
    df["target"] = df["Label"].apply(lambda x: 0 if str(x).strip().upper() == "BENIGN" else 1)

    drop_columns = ["Label", "target"]
    X = df.drop(columns=drop_columns)
    y = df["target"]

    # Keep only numeric columns
    X = X.select_dtypes(include=["int64", "float64"])

    print(f"Features used: {X.shape[1]}")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1
    )

    print("Training model...")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    print("\nModel Evaluation")
    print("----------------")
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))

    os.makedirs("models", exist_ok=True)
    joblib.dump(model, MODEL_PATH)

    feature_columns_path = "models/feature_columns.pkl"
    joblib.dump(X.columns.tolist(), feature_columns_path)

    print(f"\nModel saved to: {MODEL_PATH}")
    print(f"Feature columns saved to: {feature_columns_path}")


if __name__ == "__main__":
    train_model()
