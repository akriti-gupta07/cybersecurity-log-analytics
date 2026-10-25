from pathlib import Path
import os
import joblib
import pandas as pd

BASE = Path(__file__).resolve().parents[1]
MODEL_PATH = BASE / os.getenv("MODEL_PATH", "models/random_forest.joblib")

class ModelUnavailable(Exception):
    pass

def get_model():
    if not MODEL_PATH.exists():
        raise ModelUnavailable(
            f"Saved model not found at {MODEL_PATH}. Save your trained Random Forest and its training feature list first."
        )
    return joblib.load(MODEL_PATH)

def predict_dataframe(model, df):
    # The model artifact should be a dict with keys 'model' and 'features',
    # or a pipeline/model object with feature_names_in_.
    if isinstance(model, dict):
        estimator = model.get("model")
        features = model.get("features")
    else:
        estimator = model
        features = getattr(model, "feature_names_in_", None)
    if estimator is None or features is None:
        raise ModelUnavailable(
            "Model must be saved with its exact training feature list. Update the training script to save {'model': model, 'features': feature_names}."
        )
    missing = [str(f) for f in features if f not in df.columns]
    if missing:
        raise ValueError("CSV is missing required model features: " + ", ".join(missing[:15]))
    X = df[list(features)].copy()
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    if X.isna().any().any():
        bad = list(X.columns[X.isna().any()])[:10]
        raise ValueError("Missing or non-numeric values found in features: " + ", ".join(bad))
    y = estimator.predict(X)
    return ["Attack" if int(v) == 1 else "Normal" for v in y]
